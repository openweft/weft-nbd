package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/openweft/weft-nbd/pkg/backend"
	"github.com/openweft/weft-nbd/pkg/protocol"
)

var (
	ErrInvalidMagic     = errors.New("invalid magic")
	ErrInvalidBlocksize = errors.New("invalid blocksize")
)

const (
	defaultMaximumRequestSize = 32 * 1024 * 1024 // Support for a 32M maximum packet size is expected: https://sourceforge.net/p/nbd/mailman/message/35081223/
)

type Export struct {
	Name        string
	Description string

	Backend backend.Backend
}

// TrimmableBackend is an optional interface a backend.Backend may implement to
// support NBD_CMD_TRIM (discard/unmap). When an export's Backend satisfies this
// interface the server advertises NBD_FLAG_SEND_TRIM and dispatches TRIM
// requests to UnmapAt; otherwise TRIM is advertised as unsupported and treated
// as a no-op if a client sends it anyway. Backends that do not implement it
// remain fully backward compatible.
type TrimmableBackend interface {
	backend.Backend

	// UnmapAt discards (unmaps) length bytes starting at off. It returns the
	// number of bytes unmapped, mirroring the io.WriterAt convention.
	UnmapAt(length uint32, off int64) (int, error)
}

// exportTransmissionFlags computes the NBD transmission flags advertised for an
// export during the handshake. Every backend implements Sync, so SEND_FLUSH is
// always set; READ_ONLY is set when the server is configured read-only; and
// SEND_TRIM is set only when the export's Backend implements TrimmableBackend.
func exportTransmissionFlags(export *Export, options *Options) uint16 {
	flags := protocol.NEGOTIATION_REPLY_FLAGS_HAS_FLAGS | protocol.TRANSMISSION_FLAG_SEND_FLUSH

	if options.SupportsMultiConn {
		flags |= protocol.NEGOTIATION_REPLY_FLAGS_CAN_MULTI_CONN
	}

	if options.ReadOnly {
		flags |= protocol.TRANSMISSION_FLAG_READ_ONLY
	}

	if _, ok := export.Backend.(TrimmableBackend); ok {
		flags |= protocol.TRANSMISSION_FLAG_SEND_TRIM
	}

	return flags
}

type Options struct {
	ReadOnly bool

	MinimumBlockSize   uint32
	PreferredBlockSize uint32
	MaximumBlockSize   uint32

	MaximumRequestSize int
	SupportsMultiConn  bool
}

func Handle(conn net.Conn, exports []*Export, options *Options) error {
	if options == nil {
		options = &Options{
			ReadOnly:          false,
			SupportsMultiConn: true,
		}
	}

	if options.MinimumBlockSize == 0 {
		options.MinimumBlockSize = 1
	}

	if options.PreferredBlockSize == 0 {
		options.PreferredBlockSize = 4096
	}

	if options.MaximumBlockSize == 0 {
		options.MaximumBlockSize = defaultMaximumRequestSize
	}

	if options.MaximumRequestSize == 0 {
		options.MaximumRequestSize = defaultMaximumRequestSize
	}

	// Negotiation
	if err := binary.Write(conn, binary.BigEndian, protocol.NegotiationNewstyleHeader{
		OldstyleMagic:  protocol.NEGOTIATION_MAGIC_OLDSTYLE,
		OptionMagic:    protocol.NEGOTIATION_MAGIC_OPTION,
		HandshakeFlags: protocol.NEGOTIATION_HANDSHAKE_FLAG_FIXED_NEWSTYLE,
	}); err != nil {
		return err
	}

	_, err := io.CopyN(io.Discard, conn, 4) // Discard client flags (uint32)
	if err != nil {
		return err
	}

	var export *Export
n:
	for {
		var optionHeader protocol.NegotiationOptionHeader
		if err := binary.Read(conn, binary.BigEndian, &optionHeader); err != nil {
			return err
		}

		if optionHeader.OptionMagic != protocol.NEGOTIATION_MAGIC_OPTION {
			return ErrInvalidMagic
		}

		switch optionHeader.ID {
		case protocol.NEGOTIATION_ID_OPTION_INFO, protocol.NEGOTIATION_ID_OPTION_GO:
			var exportNameLength uint32
			if err := binary.Read(conn, binary.BigEndian, &exportNameLength); err != nil {
				return err
			}

			exportName := make([]byte, exportNameLength)
			if _, err := io.ReadFull(conn, exportName); err != nil {
				return err
			}

			for _, candidate := range exports {
				if candidate.Name == string(exportName) {
					export = candidate

					break
				}
			}

			if export == nil {
				if length := int64(optionHeader.Length) - 4 - int64(exportNameLength); length > 0 { // Discard the option's data, minus the export name length and export name we've already read
					_, err := io.CopyN(io.Discard, conn, length)
					if err != nil {
						return err
					}
				}

				if err := binary.Write(conn, binary.BigEndian, protocol.NegotiationReplyHeader{
					ReplyMagic: protocol.NEGOTIATION_MAGIC_REPLY,
					ID:         optionHeader.ID,
					Type:       protocol.NEGOTIATION_TYPE_REPLY_ERR_UNKNOWN,
					Length:     0,
				}); err != nil {
					return err
				}

				break
			}

			size, err := export.Backend.Size()
			if err != nil {
				return err
			}

			{
				var informationRequestCount uint16
				if err := binary.Read(conn, binary.BigEndian, &informationRequestCount); err != nil {
					return err
				}

				_, err := io.CopyN(io.Discard, conn, 2*int64(informationRequestCount)) // Discard information requests (uint16s)
				if err != nil {
					return err
				}
			}

			{
				transmissionFlags := exportTransmissionFlags(export, options)

				info := &bytes.Buffer{}
				if err := binary.Write(info, binary.BigEndian, protocol.NegotiationReplyInfo{
					Type:              protocol.NEGOTIATION_TYPE_INFO_EXPORT,
					Size:              uint64(size),
					TransmissionFlags: transmissionFlags,
				}); err != nil {
					return err
				}

				if err := binary.Write(conn, binary.BigEndian, protocol.NegotiationReplyHeader{
					ReplyMagic: protocol.NEGOTIATION_MAGIC_REPLY,
					ID:         optionHeader.ID,
					Type:       protocol.NEGOTIATION_TYPE_REPLY_INFO,
					Length:     uint32(info.Len()),
				}); err != nil {
					return err
				}

				if _, err := io.Copy(conn, info); err != nil {
					return err
				}
			}

			{
				info := &bytes.Buffer{}
				if err := binary.Write(info, binary.BigEndian, protocol.NegotiationReplyNameHeader{
					Type: protocol.NEGOTIATION_TYPE_INFO_NAME,
				}); err != nil {
					return err
				}

				if _, err := info.Write([]byte(exportName)); err != nil {
					return err
				}

				if err := binary.Write(conn, binary.BigEndian, protocol.NegotiationReplyHeader{
					ReplyMagic: protocol.NEGOTIATION_MAGIC_REPLY,
					ID:         optionHeader.ID,
					Type:       protocol.NEGOTIATION_TYPE_REPLY_INFO,
					Length:     uint32(info.Len()),
				}); err != nil {
					return err
				}

				if _, err := io.Copy(conn, info); err != nil {
					return err
				}
			}

			{
				info := &bytes.Buffer{}
				if err := binary.Write(info, binary.BigEndian, protocol.NegotiationReplyDescriptionHeader{
					Type: protocol.NEGOTIATION_TYPE_INFO_DESCRIPTION,
				}); err != nil {
					return err
				}

				if err := binary.Write(info, binary.BigEndian, []byte(export.Description)); err != nil {
					return err
				}

				if err := binary.Write(conn, binary.BigEndian, protocol.NegotiationReplyHeader{
					ReplyMagic: protocol.NEGOTIATION_MAGIC_REPLY,
					ID:         optionHeader.ID,
					Type:       protocol.NEGOTIATION_TYPE_REPLY_INFO,
					Length:     uint32(info.Len()),
				}); err != nil {
					return err
				}

				if _, err := io.Copy(conn, info); err != nil {
					return err
				}
			}

			{
				info := &bytes.Buffer{}
				if err := binary.Write(info, binary.BigEndian, protocol.NegotiationReplyBlockSize{
					Type:               protocol.NEGOTIATION_TYPE_INFO_BLOCKSIZE,
					MinimumBlockSize:   options.MinimumBlockSize,
					PreferredBlockSize: options.PreferredBlockSize,
					MaximumBlockSize:   options.MaximumBlockSize,
				}); err != nil {
					return err
				}

				if err := binary.Write(conn, binary.BigEndian, protocol.NegotiationReplyHeader{
					ReplyMagic: protocol.NEGOTIATION_MAGIC_REPLY,
					ID:         optionHeader.ID,
					Type:       protocol.NEGOTIATION_TYPE_REPLY_INFO,
					Length:     uint32(info.Len()),
				}); err != nil {
					return err
				}

				if _, err := io.Copy(conn, info); err != nil {
					return err
				}
			}

			if err := binary.Write(conn, binary.BigEndian, protocol.NegotiationReplyHeader{
				ReplyMagic: protocol.NEGOTIATION_MAGIC_REPLY,
				ID:         optionHeader.ID,
				Type:       protocol.NEGOTIATION_TYPE_REPLY_ACK,
				Length:     0,
			}); err != nil {
				return err
			}

			if optionHeader.ID == protocol.NEGOTIATION_ID_OPTION_GO {
				break n
			}
		case protocol.NEGOTIATION_ID_OPTION_ABORT:
			if err := binary.Write(conn, binary.BigEndian, protocol.NegotiationReplyHeader{
				ReplyMagic: protocol.NEGOTIATION_MAGIC_REPLY,
				ID:         optionHeader.ID,
				Type:       protocol.NEGOTIATION_TYPE_REPLY_ACK,
				Length:     0,
			}); err != nil {
				return err
			}

			return nil
		case protocol.NEGOTIATION_ID_OPTION_LIST:
			{
				info := &bytes.Buffer{}

				for _, export := range exports {
					exportName := []byte(export.Name)

					if err := binary.Write(info, binary.BigEndian, uint32(len(exportName))); err != nil {
						return err
					}

					if err := binary.Write(info, binary.BigEndian, exportName); err != nil {
						return err
					}
				}

				if err := binary.Write(conn, binary.BigEndian, protocol.NegotiationReplyHeader{
					ReplyMagic: protocol.NEGOTIATION_MAGIC_REPLY,
					ID:         optionHeader.ID,
					Type:       protocol.NEGOTIATION_TYPE_REPLY_SERVER,
					Length:     uint32(info.Len()),
				}); err != nil {
					return err
				}

				if _, err := io.Copy(conn, info); err != nil {
					return err
				}
			}

			if err := binary.Write(conn, binary.BigEndian, protocol.NegotiationReplyHeader{
				ReplyMagic: protocol.NEGOTIATION_MAGIC_REPLY,
				ID:         optionHeader.ID,
				Type:       protocol.NEGOTIATION_TYPE_REPLY_ACK,
				Length:     0,
			}); err != nil {
				return err
			}
		default:
			_, err := io.CopyN(io.Discard, conn, int64(optionHeader.Length)) // Discard the unknown option's data
			if err != nil {
				return err
			}

			if err := binary.Write(conn, binary.BigEndian, protocol.NegotiationReplyHeader{
				ReplyMagic: protocol.NEGOTIATION_MAGIC_REPLY,
				ID:         optionHeader.ID,
				Type:       protocol.NEGOTIATION_TYPE_REPLY_ERR_UNSUPPORTED,
				Length:     0,
			}); err != nil {
				return err
			}
		}
	}

	// Transmission
	b := []byte{}
	for {
		var requestHeader protocol.TransmissionRequestHeader
		if err := binary.Read(conn, binary.BigEndian, &requestHeader); err != nil {
			return err
		}

		if requestHeader.RequestMagic != protocol.TRANSMISSION_MAGIC_REQUEST {
			return ErrInvalidMagic
		}

		length := requestHeader.Length
		if length > defaultMaximumRequestSize {
			return ErrInvalidBlocksize
		}

		if length != uint32(len(b)) {
			b = make([]byte, length)
		}

		switch requestHeader.Type {
		case protocol.TRANSMISSION_TYPE_REQUEST_READ:
			if err := binary.Write(conn, binary.BigEndian, protocol.TransmissionReplyHeader{
				ReplyMagic: protocol.TRANSMISSION_MAGIC_REPLY,
				Error:      0,
				Handle:     requestHeader.Handle,
			}); err != nil {
				return err
			}

			n, err := export.Backend.ReadAt(b[:length], int64(requestHeader.Offset))
			if err != nil {
				return err
			}

			if _, err := conn.Write(b[:n]); err != nil {
				return err
			}
		case protocol.TRANSMISSION_TYPE_REQUEST_WRITE:
			if options.ReadOnly {
				_, err := io.CopyN(io.Discard, conn, int64(requestHeader.Length)) // Discard the write command's data
				if err != nil {
					return err
				}

				if err := binary.Write(conn, binary.BigEndian, protocol.TransmissionReplyHeader{
					ReplyMagic: protocol.TRANSMISSION_MAGIC_REPLY,
					Error:      protocol.TRANSMISSION_ERROR_EPERM,
					Handle:     requestHeader.Handle,
				}); err != nil {
					return err
				}

				break
			}

			n, err := io.ReadAtLeast(conn, b[:length], int(requestHeader.Length))
			if err != nil {
				return err
			}

			if _, err := export.Backend.WriteAt(b[:n], int64(requestHeader.Offset)); err != nil {
				return err
			}

			if err := binary.Write(conn, binary.BigEndian, protocol.TransmissionReplyHeader{
				ReplyMagic: protocol.TRANSMISSION_MAGIC_REPLY,
				Error:      0,
				Handle:     requestHeader.Handle,
			}); err != nil {
				return err
			}
		case protocol.TRANSMISSION_TYPE_REQUEST_FLUSH:
			replyError := uint32(0)
			if err := export.Backend.Sync(); err != nil {
				replyError = protocol.TRANSMISSION_ERROR_EIO
			}

			if err := binary.Write(conn, binary.BigEndian, protocol.TransmissionReplyHeader{
				ReplyMagic: protocol.TRANSMISSION_MAGIC_REPLY,
				Error:      replyError,
				Handle:     requestHeader.Handle,
			}); err != nil {
				return err
			}
		case protocol.TRANSMISSION_TYPE_REQUEST_TRIM:
			if trimmable, ok := export.Backend.(TrimmableBackend); ok {
				if _, err := trimmable.UnmapAt(requestHeader.Length, int64(requestHeader.Offset)); err != nil {
					return err
				}
			}

			if err := binary.Write(conn, binary.BigEndian, protocol.TransmissionReplyHeader{
				ReplyMagic: protocol.TRANSMISSION_MAGIC_REPLY,
				Error:      0,
				Handle:     requestHeader.Handle,
			}); err != nil {
				return err
			}
		case protocol.TRANSMISSION_TYPE_REQUEST_DISC:
			if !options.ReadOnly {
				if err := export.Backend.Sync(); err != nil {
					return err
				}
			}

			return nil
		default:
			_, err := io.CopyN(io.Discard, conn, int64(requestHeader.Length)) // Discard the unknown command's data
			if err != nil {
				return err
			}

			if err := binary.Write(conn, binary.BigEndian, protocol.TransmissionReplyHeader{
				ReplyMagic: protocol.TRANSMISSION_MAGIC_REPLY,
				Error:      protocol.TRANSMISSION_ERROR_EINVAL,
				Handle:     requestHeader.Handle,
			}); err != nil {
				return err
			}
		}
	}
}
