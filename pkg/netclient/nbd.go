// Package netclient implements a pure-Go, host-side NBD network client that
// dials OUT over TCP (optionally wrapped in TLS) to a remote NBD server,
// negotiates an export using the fixed-newstyle handshake and presents the
// negotiated export as an in-process block source.
//
// Unlike github.com/openweft/weft-nbd/pkg/client (which attaches a remote
// export to a local /dev/nbdX kernel device via ioctls), this package keeps
// the export entirely in userspace: the returned Device speaks the NBD
// transmission protocol directly and therefore satisfies both the weft-nbd
// server backend.Backend shape (io.ReaderAt + io.WriterAt + Size + Sync +
// Close) and weft-block's types.ReaderWriterUnmapperAt shape (which adds
// UnmapAt). This makes it the host-side networking "fourth corner" of
// weft-nbd, mirroring the shape of go-diskimages/qcow2.Device.
//
// Security: by design the default transport is PLAINTEXT NBD, because the
// intended deployment runs NBD inside a WireGuard tunnel where WireGuard
// provides confidentiality and integrity. TLS is available but optional: set
// Options.TLS to a non-nil *tls.Config to negotiate NBD_OPT_STARTTLS and
// upgrade the connection to TLS before the export is negotiated.
package netclient

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/openweft/weft-nbd/pkg/protocol"
)

// NBD transmission command types, transmission flags and option IDs consumed
// by this client. They alias the canonical definitions in pkg/protocol (the
// single source of truth) under the package's local lowercase naming so the
// call sites and tests read naturally. The READ / WRITE / DISC request types
// and the request / reply magics are likewise taken from pkg/protocol.
const (
	transmissionTypeRequestFlush = protocol.TRANSMISSION_TYPE_REQUEST_FLUSH // NBD_CMD_FLUSH
	transmissionTypeRequestTrim  = protocol.TRANSMISSION_TYPE_REQUEST_TRIM  // NBD_CMD_TRIM

	transmissionFlagHasFlags  = protocol.TRANSMISSION_FLAG_HAS_FLAGS  // NBD_FLAG_HAS_FLAGS
	transmissionFlagReadOnly  = protocol.TRANSMISSION_FLAG_READ_ONLY  // NBD_FLAG_READ_ONLY
	transmissionFlagSendFlush = protocol.TRANSMISSION_FLAG_SEND_FLUSH // NBD_FLAG_SEND_FLUSH
	transmissionFlagSendTrim  = protocol.TRANSMISSION_FLAG_SEND_TRIM  // NBD_FLAG_SEND_TRIM

	// negotiationIDOptionExportName is NBD_OPT_EXPORT_NAME (1), used as the
	// fallback negotiation path for servers that do not support NBD_OPT_GO.
	negotiationIDOptionExportName = protocol.NEGOTIATION_ID_OPTION_EXPORT_NAME
	// negotiationIDOptionStartTLS is NBD_OPT_STARTTLS (5).
	negotiationIDOptionStartTLS = protocol.NEGOTIATION_ID_OPTION_STARTTLS
)

// Errors returned by this package.
var (
	// ErrInvalidMagic is returned when the server sends an unexpected magic
	// number during the handshake or transmission phases.
	ErrInvalidMagic = errors.New("nbd: invalid magic")
	// ErrUnsupportedHandshake is returned when the server does not advertise
	// the fixed-newstyle handshake.
	ErrUnsupportedHandshake = errors.New("nbd: server does not support fixed-newstyle handshake")
	// ErrExportNotFound is returned when the server rejects the requested
	// export (NBD_REP_ERR_UNKNOWN) or closes the connection during an
	// NBD_OPT_EXPORT_NAME negotiation for an unknown export.
	ErrExportNotFound = errors.New("nbd: export not found")
	// ErrOptionFailed is returned when the server replies to a handshake
	// option with an error reply type other than NBD_REP_ERR_UNKNOWN.
	ErrOptionFailed = errors.New("nbd: handshake option failed")
	// ErrUnknownReply is returned when the server sends an unrecognized
	// handshake reply type.
	ErrUnknownReply = errors.New("nbd: unknown handshake reply")
	// ErrReadOnly is returned by WriteAt and UnmapAt when the negotiated
	// export is read-only.
	ErrReadOnly = errors.New("nbd: export is read-only")
	// ErrUnsupportedCommand is returned by Sync when the server did not
	// advertise NBD_FLAG_SEND_FLUSH, or by UnmapAt when the server did not
	// advertise NBD_FLAG_SEND_TRIM.
	ErrUnsupportedCommand = errors.New("nbd: command not supported by export")
	// ErrServer wraps a non-zero error code returned by the server in a
	// transmission reply.
	ErrServer = errors.New("nbd: server returned error")
	// ErrHandleMismatch is returned when a transmission reply carries a
	// handle that does not match the request that was sent.
	ErrHandleMismatch = errors.New("nbd: reply handle mismatch")
	// ErrClosed is returned by operations on a Device whose connection has
	// already been closed.
	ErrClosed = errors.New("nbd: device is closed")
	// ErrTLSNotOffered is returned when Options.TLS is set but the server
	// rejects NBD_OPT_STARTTLS.
	ErrTLSNotOffered = errors.New("nbd: server does not support STARTTLS")
)

// Options configures Dial.
type Options struct {
	// ExportName is the name of the export to negotiate. An empty name
	// negotiates the server's default export.
	ExportName string
	// ReadOnly requests a read-only attachment. When true, WriteAt and
	// UnmapAt return ErrReadOnly regardless of what the server advertises.
	ReadOnly bool
	// TLS, when non-nil, upgrades the connection to TLS via NBD_OPT_STARTTLS
	// before the export is negotiated. When nil (the default) the connection
	// stays plaintext, which is the intended mode when NBD runs inside a
	// WireGuard tunnel.
	TLS *tls.Config
}

// Device is an in-process NBD block source backed by a network connection to a
// remote NBD server. It is safe for concurrent use: a mutex serializes
// in-flight commands so that exactly one request/reply round-trip is in flight
// at a time.
//
// Device satisfies the weft-nbd backend.Backend interface (ReadAt, WriteAt,
// Size, Sync, Close) and the weft-block types.ReaderWriterUnmapperAt interface
// (ReadAt, WriteAt, UnmapAt).
type Device struct {
	mu     sync.Mutex
	conn   net.Conn
	handle uint64

	size     int64
	flags    uint16
	readOnly bool
	closed   bool
}

// Dial connects to the NBD server at addr over TCP, performs the
// fixed-newstyle handshake, negotiates the requested export and returns a
// Device ready for transmission.
//
// If ctx carries a deadline it is applied to the dial. The handshake itself is
// performed synchronously after the connection is established.
func Dial(ctx context.Context, addr string, opts Options) (*Device, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	dev, err := newDevice(conn, opts)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return dev, nil
}

// newDevice runs the handshake on an already-established connection. It is
// separated from Dial so that tests can drive the handshake over an arbitrary
// net.Conn (e.g. net.Pipe).
func newDevice(conn net.Conn, opts Options) (*Device, error) {
	if err := negotiateNewstyle(conn); err != nil {
		return nil, err
	}

	if opts.TLS != nil {
		tlsConn, err := startTLS(conn, opts.TLS)
		if err != nil {
			return nil, err
		}
		conn = tlsConn
	}

	size, flags, err := negotiateGo(conn, opts.ExportName)
	if err != nil {
		if !errors.Is(err, errOptGoUnsupported) {
			return nil, err
		}

		// Fall back to NBD_OPT_EXPORT_NAME for older servers.
		size, flags, err = negotiateExportName(conn, opts.ExportName)
		if err != nil {
			return nil, err
		}
	}

	return &Device{
		conn:     conn,
		size:     size,
		flags:    flags,
		readOnly: opts.ReadOnly || flags&transmissionFlagReadOnly != 0,
	}, nil
}

// errOptGoUnsupported signals that the server rejected NBD_OPT_GO as
// unsupported, so the caller should fall back to NBD_OPT_EXPORT_NAME.
var errOptGoUnsupported = errors.New("nbd: NBD_OPT_GO unsupported")

// negotiateNewstyle reads the server handshake header, validates the magics
// and the fixed-newstyle flag, and sends the client flags.
func negotiateNewstyle(conn net.Conn) error {
	var header protocol.NegotiationNewstyleHeader
	if err := binary.Read(conn, binary.BigEndian, &header); err != nil {
		return err
	}

	if header.OldstyleMagic != protocol.NEGOTIATION_MAGIC_OLDSTYLE {
		return ErrInvalidMagic
	}

	if header.OptionMagic != protocol.NEGOTIATION_MAGIC_OPTION {
		return ErrInvalidMagic
	}

	if header.HandshakeFlags&protocol.NEGOTIATION_HANDSHAKE_FLAG_FIXED_NEWSTYLE == 0 {
		return ErrUnsupportedHandshake
	}

	// Send client flags (uint32): acknowledge fixed-newstyle.
	if err := binary.Write(conn, binary.BigEndian, uint32(protocol.NEGOTIATION_HANDSHAKE_FLAG_FIXED_NEWSTYLE)); err != nil {
		return err
	}

	return nil
}

// startTLS performs NBD_OPT_STARTTLS and, on success, wraps conn in a TLS
// client. The TLS handshake itself is driven by the first read/write on the
// returned connection, but tls.Client returns immediately; the explicit
// Handshake call below surfaces handshake errors eagerly.
func startTLS(conn net.Conn, cfg *tls.Config) (net.Conn, error) {
	if err := writeOptionHeader(conn, negotiationIDOptionStartTLS, 0); err != nil {
		return nil, err
	}

	reply, err := readReplyHeader(conn)
	if err != nil {
		return nil, err
	}

	if reply.Length > 0 {
		if _, err := io.CopyN(io.Discard, conn, int64(reply.Length)); err != nil {
			return nil, err
		}
	}

	if reply.Type != protocol.NEGOTIATION_TYPE_REPLY_ACK {
		return nil, ErrTLSNotOffered
	}

	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	return tlsConn, nil
}

// negotiateGo negotiates the export with NBD_OPT_GO. On success it returns the
// export size and transmission flags and the connection is positioned at the
// start of the transmission phase. If the server replies that NBD_OPT_GO is
// unsupported it returns errOptGoUnsupported so the caller can fall back to
// NBD_OPT_EXPORT_NAME.
func negotiateGo(conn net.Conn, exportName string) (int64, uint16, error) {
	name := []byte(exportName)

	// Option payload: 4-byte name length + name + 2-byte info request count.
	payloadLen := uint32(4 + len(name) + 2)
	if err := writeOptionHeader(conn, protocol.NEGOTIATION_ID_OPTION_GO, payloadLen); err != nil {
		return 0, 0, err
	}

	if err := binary.Write(conn, binary.BigEndian, uint32(len(name))); err != nil {
		return 0, 0, err
	}

	if _, err := conn.Write(name); err != nil {
		return 0, 0, err
	}

	// Request zero information items: the server still sends NBD_INFO_EXPORT.
	if err := binary.Write(conn, binary.BigEndian, uint16(0)); err != nil {
		return 0, 0, err
	}

	var (
		size      uint64
		flags     uint16
		gotExport bool
	)

	for {
		reply, err := readReplyHeader(conn)
		if err != nil {
			return 0, 0, err
		}

		switch reply.Type {
		case protocol.NEGOTIATION_TYPE_REPLY_INFO:
			infoRaw := make([]byte, reply.Length)
			if _, err := io.ReadFull(conn, infoRaw); err != nil {
				return 0, 0, err
			}

			if len(infoRaw) < 2 {
				return 0, 0, ErrUnknownReply
			}

			infoType := binary.BigEndian.Uint16(infoRaw[:2])
			if infoType == protocol.NEGOTIATION_TYPE_INFO_EXPORT {
				var info protocol.NegotiationReplyInfo
				if err := binary.Read(newReader(infoRaw), binary.BigEndian, &info); err != nil {
					return 0, 0, err
				}
				size = info.Size
				flags = info.TransmissionFlags
				gotExport = true
			}
			// Other NBD_INFO_* records (NAME, DESCRIPTION, BLOCKSIZE) are
			// accepted and ignored.
		case protocol.NEGOTIATION_TYPE_REPLY_ACK:
			if !gotExport {
				return 0, 0, ErrUnknownReply
			}
			return int64(size), flags, nil
		case protocol.NEGOTIATION_TYPE_REPLY_ERR_UNSUPPORTED:
			if reply.Length > 0 {
				if _, err := io.CopyN(io.Discard, conn, int64(reply.Length)); err != nil {
					return 0, 0, err
				}
			}
			return 0, 0, errOptGoUnsupported
		case protocol.NEGOTIATION_TYPE_REPLY_ERR_UNKNOWN:
			if reply.Length > 0 {
				if _, err := io.CopyN(io.Discard, conn, int64(reply.Length)); err != nil {
					return 0, 0, err
				}
			}
			return 0, 0, ErrExportNotFound
		default:
			if reply.Type&(uint32(1)<<31) != 0 {
				// Any other error reply.
				if reply.Length > 0 {
					if _, err := io.CopyN(io.Discard, conn, int64(reply.Length)); err != nil {
						return 0, 0, err
					}
				}
				return 0, 0, ErrOptionFailed
			}
			return 0, 0, ErrUnknownReply
		}
	}
}

// negotiateExportName negotiates the export with NBD_OPT_EXPORT_NAME, the
// legacy path. The server responds with the export size and transmission
// flags followed by 124 bytes of zeroes (unless NBD_FLAG_NO_ZEROES was
// negotiated, which this client does not request), then enters transmission.
func negotiateExportName(conn net.Conn, exportName string) (int64, uint16, error) {
	name := []byte(exportName)

	if err := writeOptionHeader(conn, negotiationIDOptionExportName, uint32(len(name))); err != nil {
		return 0, 0, err
	}

	if _, err := conn.Write(name); err != nil {
		return 0, 0, err
	}

	// Reply: uint64 size, uint16 transmission flags, 124 bytes of padding.
	var reply struct {
		Size  uint64
		Flags uint16
	}
	if err := binary.Read(conn, binary.BigEndian, &reply); err != nil {
		// An unknown export causes the server to drop the connection.
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, 0, ErrExportNotFound
		}
		return 0, 0, err
	}

	if _, err := io.CopyN(io.Discard, conn, 124); err != nil {
		return 0, 0, err
	}

	return int64(reply.Size), reply.Flags, nil
}

// transact sends a transmission request header (optionally followed by a data
// payload) and reads the simple reply, validating the magic and matching the
// handle. For read commands the caller passes a non-nil readInto buffer to
// receive the reply payload. The caller must hold d.mu.
func (d *Device) transact(reqType uint16, offset uint64, length uint32, writeData []byte, readInto []byte) error {
	if d.closed {
		return ErrClosed
	}

	handle := d.handle
	d.handle++

	req := protocol.TransmissionRequestHeader{
		RequestMagic: protocol.TRANSMISSION_MAGIC_REQUEST,
		CommandFlags: 0,
		Type:         reqType,
		Handle:       handle,
		Offset:       offset,
		Length:       length,
	}

	if err := binary.Write(d.conn, binary.BigEndian, req); err != nil {
		return err
	}

	if writeData != nil {
		if _, err := d.conn.Write(writeData); err != nil {
			return err
		}
	}

	var reply protocol.TransmissionReplyHeader
	if err := binary.Read(d.conn, binary.BigEndian, &reply); err != nil {
		return err
	}

	if reply.ReplyMagic != protocol.TRANSMISSION_MAGIC_REPLY {
		return ErrInvalidMagic
	}

	if reply.Handle != handle {
		return ErrHandleMismatch
	}

	if reply.Error != 0 {
		return ErrServer
	}

	if readInto != nil {
		if _, err := io.ReadFull(d.conn, readInto); err != nil {
			return err
		}
	}

	return nil
}

// ReadAt implements io.ReaderAt by issuing NBD_CMD_READ. It reads len(p) bytes
// starting at off and always fills p completely on success.
func (d *Device) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.transact(protocol.TRANSMISSION_TYPE_REQUEST_READ, uint64(off), uint32(len(p)), nil, p); err != nil {
		return 0, err
	}

	return len(p), nil
}

// WriteAt implements io.WriterAt by issuing NBD_CMD_WRITE. It returns
// ErrReadOnly without contacting the server when the export is read-only.
func (d *Device) WriteAt(p []byte, off int64) (int, error) {
	if d.readOnly {
		return 0, ErrReadOnly
	}

	if len(p) == 0 {
		return 0, nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.transact(protocol.TRANSMISSION_TYPE_REQUEST_WRITE, uint64(off), uint32(len(p)), p, nil); err != nil {
		return 0, err
	}

	return len(p), nil
}

// UnmapAt implements weft-block's types.UnmapperAt by issuing NBD_CMD_TRIM,
// discarding length bytes starting at off. It returns ErrReadOnly on a
// read-only export and ErrUnsupportedCommand when the server did not advertise
// NBD_FLAG_SEND_TRIM. On success it reports length bytes unmapped.
func (d *Device) UnmapAt(length uint32, off int64) (int, error) {
	if d.readOnly {
		return 0, ErrReadOnly
	}

	if d.flags&transmissionFlagSendTrim == 0 {
		return 0, ErrUnsupportedCommand
	}

	if length == 0 {
		return 0, nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.transact(transmissionTypeRequestTrim, uint64(off), length, nil, nil); err != nil {
		return 0, err
	}

	return int(length), nil
}

// Sync implements backend.Backend by issuing NBD_CMD_FLUSH. It returns
// ErrUnsupportedCommand when the server did not advertise NBD_FLAG_SEND_FLUSH.
func (d *Device) Sync() error {
	if d.flags&transmissionFlagSendFlush == 0 {
		return ErrUnsupportedCommand
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	return d.transact(transmissionTypeRequestFlush, 0, 0, nil, nil)
}

// Size returns the negotiated export size in bytes.
func (d *Device) Size() (int64, error) {
	return d.size, nil
}

// Close issues a best-effort NBD_CMD_DISC and closes the underlying
// connection. NBD_CMD_DISC has no reply, so any write error is reported only
// via the subsequent connection close. Close is idempotent.
func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil
	}
	d.closed = true

	// Best-effort disconnect: the server has no obligation to reply.
	_ = binary.Write(d.conn, binary.BigEndian, protocol.TransmissionRequestHeader{
		RequestMagic: protocol.TRANSMISSION_MAGIC_REQUEST,
		Type:         protocol.TRANSMISSION_TYPE_REQUEST_DISC,
		Handle:       d.handle,
	})
	d.handle++

	return d.conn.Close()
}

// writeOptionHeader writes a negotiation option header.
func writeOptionHeader(conn net.Conn, id uint32, length uint32) error {
	return binary.Write(conn, binary.BigEndian, protocol.NegotiationOptionHeader{
		OptionMagic: protocol.NEGOTIATION_MAGIC_OPTION,
		ID:          id,
		Length:      length,
	})
}

// readReplyHeader reads and validates a negotiation reply header.
func readReplyHeader(conn net.Conn) (protocol.NegotiationReplyHeader, error) {
	var reply protocol.NegotiationReplyHeader
	if err := binary.Read(conn, binary.BigEndian, &reply); err != nil {
		return reply, err
	}

	if reply.ReplyMagic != protocol.NEGOTIATION_MAGIC_REPLY {
		return reply, ErrInvalidMagic
	}

	return reply, nil
}

// newReader returns an io.Reader over b. It exists so binary.Read can consume a
// byte slice without pulling in bytes.NewReader at every call site.
func newReader(b []byte) io.Reader {
	return &sliceReader{b: b}
}

type sliceReader struct {
	b   []byte
	off int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.off >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.off:])
	r.off += n
	return n, nil
}
