package netclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/openweft/weft-nbd/pkg/protocol"
)

// fakeServer implements the server side of the NBD handshake and transmission
// over a net.Conn so the client can be exercised end to end.
type fakeServer struct {
	conn net.Conn

	exportName string
	size       uint64
	flags      uint16

	// behaviour toggles
	badServerMagic   bool // send wrong OldstyleMagic
	noFixedNewstyle  bool // omit fixed-newstyle handshake flag
	useExportName    bool // reject NBD_OPT_GO so client falls back
	unknownExport    bool // reply NBD_REP_ERR_UNKNOWN to NBD_OPT_GO
	optionError      bool // reply with a generic option error to NBD_OPT_GO
	ackWithoutExport bool // send NBD_REP_ACK without an NBD_INFO_EXPORT
	goReplyBadMagic  bool // corrupt the negotiation reply magic
	badInfoLen       bool // send an info record shorter than 2 bytes
	dropOnExportName bool // drop connection on NBD_OPT_EXPORT_NAME (unknown)
	offerTLS         bool // accept NBD_OPT_STARTTLS
	tlsConfig        *tls.Config

	// transmission toggles
	replyTxMagicBad bool // corrupt the transmission reply magic
	replyHandleBad  bool // corrupt the reply handle
	replyError      uint32
	shortRead       bool // send fewer payload bytes than requested for READ

	backing []byte

	mu  sync.Mutex
	got struct {
		disc bool
	}
}

func (s *fakeServer) run(t *testing.T) {
	t.Helper()
	defer s.conn.Close()

	conn := s.conn

	// --- Handshake ---
	oldMagic := protocol.NEGOTIATION_MAGIC_OLDSTYLE
	if s.badServerMagic {
		oldMagic = 0xdeadbeef
	}
	hsFlags := protocol.NEGOTIATION_HANDSHAKE_FLAG_FIXED_NEWSTYLE
	if s.noFixedNewstyle {
		hsFlags = 0
	}
	if err := binary.Write(conn, binary.BigEndian, protocol.NegotiationNewstyleHeader{
		OldstyleMagic:  oldMagic,
		OptionMagic:    protocol.NEGOTIATION_MAGIC_OPTION,
		HandshakeFlags: hsFlags,
	}); err != nil {
		return
	}
	if s.badServerMagic || s.noFixedNewstyle {
		return
	}

	// Read client flags (uint32).
	var clientFlags uint32
	if err := binary.Read(conn, binary.BigEndian, &clientFlags); err != nil {
		return
	}

	// --- Options ---
	for {
		var opt protocol.NegotiationOptionHeader
		if err := binary.Read(conn, binary.BigEndian, &opt); err != nil {
			return
		}

		switch opt.ID {
		case negotiationIDOptionStartTLS:
			if !s.offerTLS {
				_ = binary.Write(conn, binary.BigEndian, protocol.NegotiationReplyHeader{
					ReplyMagic: protocol.NEGOTIATION_MAGIC_REPLY,
					ID:         opt.ID,
					Type:       protocol.NEGOTIATION_TYPE_REPLY_ERR_UNSUPPORTED,
					Length:     0,
				})
				continue
			}
			_ = binary.Write(conn, binary.BigEndian, protocol.NegotiationReplyHeader{
				ReplyMagic: protocol.NEGOTIATION_MAGIC_REPLY,
				ID:         opt.ID,
				Type:       protocol.NEGOTIATION_TYPE_REPLY_ACK,
				Length:     0,
			})
			tlsConn := tls.Server(conn, s.tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn

		case protocol.NEGOTIATION_ID_OPTION_GO:
			// Read name length + name + info request count.
			var nameLen uint32
			if err := binary.Read(conn, binary.BigEndian, &nameLen); err != nil {
				return
			}
			name := make([]byte, nameLen)
			if _, err := io.ReadFull(conn, name); err != nil {
				return
			}
			var infoCount uint16
			if err := binary.Read(conn, binary.BigEndian, &infoCount); err != nil {
				return
			}
			if _, err := io.CopyN(io.Discard, conn, 2*int64(infoCount)); err != nil {
				return
			}

			replyMagic := protocol.NEGOTIATION_MAGIC_REPLY
			if s.goReplyBadMagic {
				replyMagic = 0x12345
			}

			if s.useExportName {
				_ = binary.Write(conn, binary.BigEndian, protocol.NegotiationReplyHeader{
					ReplyMagic: replyMagic,
					ID:         opt.ID,
					Type:       protocol.NEGOTIATION_TYPE_REPLY_ERR_UNSUPPORTED,
					Length:     0,
				})
				continue
			}
			if s.unknownExport {
				_ = binary.Write(conn, binary.BigEndian, protocol.NegotiationReplyHeader{
					ReplyMagic: replyMagic,
					ID:         opt.ID,
					Type:       protocol.NEGOTIATION_TYPE_REPLY_ERR_UNKNOWN,
					Length:     3,
				})
				_, _ = conn.Write([]byte{1, 2, 3})
				return
			}
			if s.optionError {
				_ = binary.Write(conn, binary.BigEndian, protocol.NegotiationReplyHeader{
					ReplyMagic: replyMagic,
					ID:         opt.ID,
					Type:       uint32(99) | uint32(1<<31),
					Length:     2,
				})
				_, _ = conn.Write([]byte{0, 0})
				return
			}
			if s.goReplyBadMagic {
				_ = binary.Write(conn, binary.BigEndian, protocol.NegotiationReplyHeader{
					ReplyMagic: replyMagic,
					ID:         opt.ID,
					Type:       protocol.NEGOTIATION_TYPE_REPLY_ACK,
					Length:     0,
				})
				return
			}
			if s.badInfoLen {
				_ = binary.Write(conn, binary.BigEndian, protocol.NegotiationReplyHeader{
					ReplyMagic: replyMagic,
					ID:         opt.ID,
					Type:       protocol.NEGOTIATION_TYPE_REPLY_INFO,
					Length:     1,
				})
				_, _ = conn.Write([]byte{0})
				return
			}

			if !s.ackWithoutExport {
				// NBD_INFO_EXPORT record.
				info := &bytes.Buffer{}
				_ = binary.Write(info, binary.BigEndian, protocol.NegotiationReplyInfo{
					Type:              protocol.NEGOTIATION_TYPE_INFO_EXPORT,
					Size:              s.size,
					TransmissionFlags: s.flags,
				})
				_ = binary.Write(conn, binary.BigEndian, protocol.NegotiationReplyHeader{
					ReplyMagic: replyMagic,
					ID:         opt.ID,
					Type:       protocol.NEGOTIATION_TYPE_REPLY_INFO,
					Length:     uint32(info.Len()),
				})
				_, _ = conn.Write(info.Bytes())

				// An extra ignored NBD_INFO_NAME record to exercise the skip path.
				nameInfo := &bytes.Buffer{}
				_ = binary.Write(nameInfo, binary.BigEndian, protocol.NEGOTIATION_TYPE_INFO_NAME)
				nameInfo.WriteString("ignored")
				_ = binary.Write(conn, binary.BigEndian, protocol.NegotiationReplyHeader{
					ReplyMagic: replyMagic,
					ID:         opt.ID,
					Type:       protocol.NEGOTIATION_TYPE_REPLY_INFO,
					Length:     uint32(nameInfo.Len()),
				})
				_, _ = conn.Write(nameInfo.Bytes())
			}

			_ = binary.Write(conn, binary.BigEndian, protocol.NegotiationReplyHeader{
				ReplyMagic: replyMagic,
				ID:         opt.ID,
				Type:       protocol.NEGOTIATION_TYPE_REPLY_ACK,
				Length:     0,
			})
			if s.ackWithoutExport {
				return
			}
			s.transmission(conn)
			return

		case negotiationIDOptionExportName:
			name := make([]byte, opt.Length)
			if _, err := io.ReadFull(conn, name); err != nil {
				return
			}
			if s.dropOnExportName {
				return
			}
			_ = binary.Write(conn, binary.BigEndian, s.size)
			_ = binary.Write(conn, binary.BigEndian, s.flags)
			_, _ = conn.Write(make([]byte, 124))
			s.transmission(conn)
			return

		default:
			_ = binary.Write(conn, binary.BigEndian, protocol.NegotiationReplyHeader{
				ReplyMagic: protocol.NEGOTIATION_MAGIC_REPLY,
				ID:         opt.ID,
				Type:       protocol.NEGOTIATION_TYPE_REPLY_ERR_UNSUPPORTED,
				Length:     0,
			})
		}
	}
}

func (s *fakeServer) transmission(conn net.Conn) {
	for {
		var req protocol.TransmissionRequestHeader
		if err := binary.Read(conn, binary.BigEndian, &req); err != nil {
			return
		}
		if req.RequestMagic != protocol.TRANSMISSION_MAGIC_REQUEST {
			return
		}

		replyMagic := protocol.TRANSMISSION_MAGIC_REPLY
		if s.replyTxMagicBad {
			replyMagic = 0xbadbad
		}
		handle := req.Handle
		if s.replyHandleBad {
			handle = req.Handle + 1000
		}

		switch req.Type {
		case protocol.TRANSMISSION_TYPE_REQUEST_READ:
			_ = binary.Write(conn, binary.BigEndian, protocol.TransmissionReplyHeader{
				ReplyMagic: replyMagic,
				Error:      s.replyError,
				Handle:     handle,
			})
			if s.replyError != 0 || s.replyTxMagicBad || s.replyHandleBad {
				return
			}
			n := int(req.Length)
			if s.shortRead {
				n = n / 2
			}
			_, _ = conn.Write(s.backing[req.Offset : req.Offset+uint64(n)])
			if s.shortRead {
				return
			}

		case protocol.TRANSMISSION_TYPE_REQUEST_WRITE:
			data := make([]byte, req.Length)
			if _, err := io.ReadFull(conn, data); err != nil {
				return
			}
			copy(s.backing[req.Offset:], data)
			_ = binary.Write(conn, binary.BigEndian, protocol.TransmissionReplyHeader{
				ReplyMagic: replyMagic,
				Error:      s.replyError,
				Handle:     handle,
			})
			if s.replyError != 0 || s.replyTxMagicBad || s.replyHandleBad {
				return
			}

		case transmissionTypeRequestFlush:
			_ = binary.Write(conn, binary.BigEndian, protocol.TransmissionReplyHeader{
				ReplyMagic: replyMagic,
				Error:      0,
				Handle:     handle,
			})

		case transmissionTypeRequestTrim:
			_ = binary.Write(conn, binary.BigEndian, protocol.TransmissionReplyHeader{
				ReplyMagic: replyMagic,
				Error:      0,
				Handle:     handle,
			})

		case protocol.TRANSMISSION_TYPE_REQUEST_DISC:
			s.mu.Lock()
			s.got.disc = true
			s.mu.Unlock()
			return
		}
	}
}

// dialFake wires a fakeServer to a client over net.Pipe and returns the Device
// plus a channel that is closed when the server goroutine exits.
func dialFake(t *testing.T, s *fakeServer, opts Options) (*Device, chan struct{}, error) {
	t.Helper()
	cConn, sConn := net.Pipe()
	s.conn = sConn

	done := make(chan struct{})
	go func() {
		s.run(t)
		close(done)
	}()
	t.Cleanup(func() { <-done })

	t.Cleanup(func() { cConn.Close() })

	type result struct {
		dev *Device
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		dev, err := newDevice(cConn, opts)
		resCh <- result{dev, err}
	}()

	select {
	case r := <-resCh:
		if r.err != nil {
			cConn.Close()
		}
		return r.dev, done, r.err
	case <-time.After(5 * time.Second):
		cConn.Close()
		t.Fatal("handshake timed out")
		return nil, done, nil
	}
}

const allFlags = transmissionFlagHasFlags | transmissionFlagSendFlush | transmissionFlagSendTrim

func newBacking() []byte {
	b := make([]byte, 4096)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestHandshakeAndRoundTrips(t *testing.T) {
	backing := newBacking()
	s := &fakeServer{
		exportName: "vol1",
		size:       4096,
		flags:      allFlags,
		backing:    backing,
	}
	dev, done, err := dialFake(t, s, Options{ExportName: "vol1"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	sz, err := dev.Size()
	if err != nil || sz != 4096 {
		t.Fatalf("size = %d, %v", sz, err)
	}

	// Read.
	p := make([]byte, 16)
	n, err := dev.ReadAt(p, 32)
	if err != nil || n != 16 {
		t.Fatalf("read: n=%d err=%v", n, err)
	}
	if !bytes.Equal(p, backing[32:48]) {
		t.Fatalf("read mismatch: %v vs %v", p, backing[32:48])
	}

	// Write.
	payload := []byte("hello world AB!!")
	n, err = dev.WriteAt(payload, 100)
	if err != nil || n != len(payload) {
		t.Fatalf("write: n=%d err=%v", n, err)
	}
	if !bytes.Equal(backing[100:100+len(payload)], payload) {
		t.Fatalf("write not applied")
	}

	// Flush.
	if err := dev.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}

	// Trim.
	un, err := dev.UnmapAt(64, 200)
	if err != nil || un != 64 {
		t.Fatalf("unmap: n=%d err=%v", un, err)
	}

	// Zero-length fast paths.
	if n, err := dev.ReadAt(nil, 0); n != 0 || err != nil {
		t.Fatalf("empty read: %d %v", n, err)
	}
	if n, err := dev.WriteAt(nil, 0); n != 0 || err != nil {
		t.Fatalf("empty write: %d %v", n, err)
	}
	if n, err := dev.UnmapAt(0, 0); n != 0 || err != nil {
		t.Fatalf("empty unmap: %d %v", n, err)
	}

	// Close sends DISC.
	if err := dev.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Idempotent.
	if err := dev.Close(); err != nil {
		t.Fatalf("double close: %v", err)
	}

	// Wait for the server goroutine to observe the DISC and exit.
	<-done

	s.mu.Lock()
	gotDisc := s.got.disc
	s.mu.Unlock()
	if !gotDisc {
		t.Fatal("server did not receive DISC")
	}

	// Operations after Close fail.
	if _, err := dev.ReadAt(make([]byte, 4), 0); !errors.Is(err, ErrClosed) {
		t.Fatalf("read after close: %v", err)
	}
}

func TestExportNameFallback(t *testing.T) {
	backing := newBacking()
	s := &fakeServer{
		size:          2048,
		flags:         transmissionFlagHasFlags,
		backing:       backing,
		useExportName: true,
	}
	dev, _, err := dialFake(t, s, Options{ExportName: "legacy"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if sz, _ := dev.Size(); sz != 2048 {
		t.Fatalf("size = %d", sz)
	}
	p := make([]byte, 8)
	if _, err := dev.ReadAt(p, 0); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(p, backing[0:8]) {
		t.Fatal("read mismatch on fallback path")
	}
	dev.Close()
}

func TestBadServerMagic(t *testing.T) {
	_, _, err := dialFake(t, &fakeServer{badServerMagic: true}, Options{})
	if !errors.Is(err, ErrInvalidMagic) {
		t.Fatalf("want ErrInvalidMagic, got %v", err)
	}
}

func TestBadOptionMagic(t *testing.T) {
	// Server with valid old magic but wrong option magic.
	cConn, sConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		_ = binary.Write(sConn, binary.BigEndian, protocol.NegotiationNewstyleHeader{
			OldstyleMagic:  protocol.NEGOTIATION_MAGIC_OLDSTYLE,
			OptionMagic:    0xdead,
			HandshakeFlags: protocol.NEGOTIATION_HANDSHAKE_FLAG_FIXED_NEWSTYLE,
		})
		sConn.Close()
		close(done)
	}()
	_, err := newDevice(cConn, Options{})
	<-done
	cConn.Close()
	if !errors.Is(err, ErrInvalidMagic) {
		t.Fatalf("want ErrInvalidMagic, got %v", err)
	}
}

func TestNoFixedNewstyle(t *testing.T) {
	_, _, err := dialFake(t, &fakeServer{noFixedNewstyle: true}, Options{})
	if !errors.Is(err, ErrUnsupportedHandshake) {
		t.Fatalf("want ErrUnsupportedHandshake, got %v", err)
	}
}

func TestHandshakeReadError(t *testing.T) {
	// Server closes immediately: client read of the header fails.
	cConn, sConn := net.Pipe()
	sConn.Close()
	_, err := newDevice(cConn, Options{})
	cConn.Close()
	if err == nil {
		t.Fatal("expected error on closed connection")
	}
}

func TestUnknownExport(t *testing.T) {
	_, _, err := dialFake(t, &fakeServer{unknownExport: true, size: 1}, Options{ExportName: "missing"})
	if !errors.Is(err, ErrExportNotFound) {
		t.Fatalf("want ErrExportNotFound, got %v", err)
	}
}

func TestOptionError(t *testing.T) {
	_, _, err := dialFake(t, &fakeServer{optionError: true, size: 1}, Options{})
	if !errors.Is(err, ErrOptionFailed) {
		t.Fatalf("want ErrOptionFailed, got %v", err)
	}
}

func TestAckWithoutExport(t *testing.T) {
	_, _, err := dialFake(t, &fakeServer{ackWithoutExport: true}, Options{})
	if !errors.Is(err, ErrUnknownReply) {
		t.Fatalf("want ErrUnknownReply, got %v", err)
	}
}

func TestGoReplyBadMagic(t *testing.T) {
	_, _, err := dialFake(t, &fakeServer{goReplyBadMagic: true, size: 1}, Options{})
	if !errors.Is(err, ErrInvalidMagic) {
		t.Fatalf("want ErrInvalidMagic, got %v", err)
	}
}

func TestBadInfoLen(t *testing.T) {
	_, _, err := dialFake(t, &fakeServer{badInfoLen: true, size: 1}, Options{})
	if !errors.Is(err, ErrUnknownReply) {
		t.Fatalf("want ErrUnknownReply, got %v", err)
	}
}

func TestExportNameNotFound(t *testing.T) {
	_, _, err := dialFake(t, &fakeServer{useExportName: true, dropOnExportName: true}, Options{ExportName: "x"})
	if !errors.Is(err, ErrExportNotFound) {
		t.Fatalf("want ErrExportNotFound, got %v", err)
	}
}

func TestReadOnlyFromServerFlag(t *testing.T) {
	s := &fakeServer{size: 512, flags: transmissionFlagHasFlags | transmissionFlagReadOnly, backing: newBacking()}
	dev, _, err := dialFake(t, s, Options{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := dev.WriteAt([]byte{1}, 0); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("want ErrReadOnly, got %v", err)
	}
	if _, err := dev.UnmapAt(1, 0); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("unmap want ErrReadOnly, got %v", err)
	}
	dev.Close()
}

func TestReadOnlyFromOption(t *testing.T) {
	s := &fakeServer{size: 512, flags: allFlags, backing: newBacking()}
	dev, _, err := dialFake(t, s, Options{ReadOnly: true})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := dev.WriteAt([]byte{1}, 0); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("want ErrReadOnly, got %v", err)
	}
	dev.Close()
}

func TestUnsupportedFlushTrim(t *testing.T) {
	s := &fakeServer{size: 512, flags: transmissionFlagHasFlags, backing: newBacking()}
	dev, _, err := dialFake(t, s, Options{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := dev.Sync(); !errors.Is(err, ErrUnsupportedCommand) {
		t.Fatalf("flush want ErrUnsupportedCommand, got %v", err)
	}
	if _, err := dev.UnmapAt(4, 0); !errors.Is(err, ErrUnsupportedCommand) {
		t.Fatalf("trim want ErrUnsupportedCommand, got %v", err)
	}
	dev.Close()
}

func TestServerErrorReply(t *testing.T) {
	s := &fakeServer{size: 512, flags: allFlags, backing: newBacking(), replyError: protocol.TRANSMISSION_ERROR_EINVAL}
	dev, _, err := dialFake(t, s, Options{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := dev.ReadAt(make([]byte, 8), 0); !errors.Is(err, ErrServer) {
		t.Fatalf("want ErrServer, got %v", err)
	}
	dev.Close()
}

func TestServerWriteErrorReply(t *testing.T) {
	s := &fakeServer{size: 512, flags: allFlags, backing: newBacking(), replyError: protocol.TRANSMISSION_ERROR_EPERM}
	dev, _, err := dialFake(t, s, Options{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := dev.WriteAt([]byte{1, 2}, 0); !errors.Is(err, ErrServer) {
		t.Fatalf("want ErrServer, got %v", err)
	}
	dev.Close()
}

func TestReplyBadMagic(t *testing.T) {
	s := &fakeServer{size: 512, flags: allFlags, backing: newBacking(), replyTxMagicBad: true}
	dev, _, err := dialFake(t, s, Options{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := dev.ReadAt(make([]byte, 8), 0); !errors.Is(err, ErrInvalidMagic) {
		t.Fatalf("want ErrInvalidMagic, got %v", err)
	}
	dev.Close()
}

func TestReplyHandleMismatch(t *testing.T) {
	s := &fakeServer{size: 512, flags: allFlags, backing: newBacking(), replyHandleBad: true}
	dev, _, err := dialFake(t, s, Options{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := dev.ReadAt(make([]byte, 8), 0); !errors.Is(err, ErrHandleMismatch) {
		t.Fatalf("want ErrHandleMismatch, got %v", err)
	}
	dev.Close()
}

func TestShortRead(t *testing.T) {
	s := &fakeServer{size: 512, flags: allFlags, backing: newBacking(), shortRead: true}
	dev, _, err := dialFake(t, s, Options{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := dev.ReadAt(make([]byte, 16), 0); err == nil {
		t.Fatal("expected short read error")
	}
	dev.Close()
}

// TestDialTCP exercises the public Dial path over a real localhost listener,
// covering the successful branch and a dial failure.
func TestDialTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	backing := newBacking()
	srvDone := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(srvDone)
			return
		}
		s := &fakeServer{conn: c, size: 4096, flags: allFlags, backing: backing}
		s.run(t)
		close(srvDone)
	}()

	dev, err := Dial(context.Background(), ln.Addr().String(), Options{ExportName: "default"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	p := make([]byte, 8)
	if _, err := dev.ReadAt(p, 0); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(p, backing[0:8]) {
		t.Fatal("read mismatch over TCP")
	}
	dev.Close()
	<-srvDone
}

func TestDialFailure(t *testing.T) {
	// Port 0 is unconnectable; connecting to a closed address yields an error.
	_, err := Dial(context.Background(), "127.0.0.1:1", Options{})
	if err == nil {
		t.Fatal("expected dial error")
	}
}

func TestDialHandshakeError(t *testing.T) {
	// A listener that accepts then immediately closes drives the handshake
	// failure branch inside Dial (so conn.Close in Dial is exercised).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Close()
	}()
	if _, err := Dial(context.Background(), ln.Addr().String(), Options{}); err == nil {
		t.Fatal("expected handshake error")
	}
}

// --- TLS / STARTTLS ---

func genTLSConfigs(t *testing.T) (server *tls.Config, client *tls.Config) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	pool := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(der)
	pool.AddCert(parsed)
	server = &tls.Config{Certificates: []tls.Certificate{cert}}
	client = &tls.Config{RootCAs: pool, ServerName: "localhost"}
	return
}

func TestStartTLSSuccess(t *testing.T) {
	srvCfg, cliCfg := genTLSConfigs(t)
	backing := newBacking()
	s := &fakeServer{
		size:      4096,
		flags:     allFlags,
		backing:   backing,
		offerTLS:  true,
		tlsConfig: srvCfg,
	}
	dev, _, err := dialFake(t, s, Options{TLS: cliCfg})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	p := make([]byte, 8)
	if _, err := dev.ReadAt(p, 0); err != nil {
		t.Fatalf("read over TLS: %v", err)
	}
	if !bytes.Equal(p, backing[0:8]) {
		t.Fatal("TLS read mismatch")
	}
	dev.Close()
}

func TestStartTLSNotOffered(t *testing.T) {
	_, cliCfg := genTLSConfigs(t)
	s := &fakeServer{size: 4096, flags: allFlags, backing: newBacking(), offerTLS: false}
	_, _, err := dialFake(t, s, Options{TLS: cliCfg})
	if !errors.Is(err, ErrTLSNotOffered) {
		t.Fatalf("want ErrTLSNotOffered, got %v", err)
	}
}

func TestStartTLSHandshakeFails(t *testing.T) {
	// Server accepts STARTTLS but the client uses a config that cannot verify
	// the (untrusted) server certificate, so the TLS handshake fails.
	srvCfg, _ := genTLSConfigs(t)
	badClient := &tls.Config{ServerName: "localhost"} // empty RootCAs -> verify fails
	s := &fakeServer{size: 4096, flags: allFlags, backing: newBacking(), offerTLS: true, tlsConfig: srvCfg}
	_, _, err := dialFake(t, s, Options{TLS: badClient})
	if err == nil {
		t.Fatal("expected TLS handshake failure")
	}
}

// TestInterfaceSatisfaction asserts at compile time that *Device satisfies both
// the weft-nbd backend.Backend shape and weft-block's
// types.ReaderWriterUnmapperAt shape, via locally-declared mirrors of those
// interfaces (importing weft-block here would create a module dependency).
func TestInterfaceSatisfaction(t *testing.T) {
	type backendBackend interface {
		io.ReaderAt
		io.WriterAt
		Size() (int64, error)
		Sync() error
		Close() error
	}
	type readerWriterUnmapperAt interface {
		io.ReaderAt
		io.WriterAt
		UnmapAt(length uint32, off int64) (n int, err error)
	}
	var _ backendBackend = (*Device)(nil)
	var _ readerWriterUnmapperAt = (*Device)(nil)
}

// TestStartTLSReplyWithPayload covers the branch where the STARTTLS reply
// carries a payload that must be discarded before the ACK/err decision.
func TestStartTLSReplyWithPayload(t *testing.T) {
	cConn, sConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer sConn.Close()
		_ = binary.Write(sConn, binary.BigEndian, protocol.NegotiationNewstyleHeader{
			OldstyleMagic:  protocol.NEGOTIATION_MAGIC_OLDSTYLE,
			OptionMagic:    protocol.NEGOTIATION_MAGIC_OPTION,
			HandshakeFlags: protocol.NEGOTIATION_HANDSHAKE_FLAG_FIXED_NEWSTYLE,
		})
		var cf uint32
		_ = binary.Read(sConn, binary.BigEndian, &cf)
		var opt protocol.NegotiationOptionHeader
		_ = binary.Read(sConn, binary.BigEndian, &opt)
		// Reply ERR_UNSUPPORTED but with a non-zero payload to discard.
		_ = binary.Write(sConn, binary.BigEndian, protocol.NegotiationReplyHeader{
			ReplyMagic: protocol.NEGOTIATION_MAGIC_REPLY,
			ID:         opt.ID,
			Type:       protocol.NEGOTIATION_TYPE_REPLY_ERR_UNSUPPORTED,
			Length:     3,
		})
		_, _ = sConn.Write([]byte{9, 9, 9})
		close(done)
	}()
	_, cliCfg := genTLSConfigs(t)
	_, err := newDevice(cConn, Options{TLS: cliCfg})
	<-done
	cConn.Close()
	if !errors.Is(err, ErrTLSNotOffered) {
		t.Fatalf("want ErrTLSNotOffered, got %v", err)
	}
}

// --- Fault-injection: a fully scripted net.Conn ---

var errFault = errors.New("injected fault")

// scriptConn is a net.Conn whose Read serves from a fixed byte script and
// whose Write counts bytes. It returns errFault from Read once the script is
// exhausted (or earlier, if readFailAt is set), and from Write once writeFailAt
// bytes have been written. This gives deterministic, synchronous control over
// every I/O error branch in the client without spawning a server goroutine.
type scriptConn struct {
	script     []byte
	roff       int
	readFailAt int // fail Read once roff reaches this (0 => after script end)

	written      int
	writeFailAt  int  // fail Write once written reaches this (0 => never)
	writeFailNow bool // fail the very first Write
}

func (c *scriptConn) Read(p []byte) (int, error) {
	if c.readFailAt > 0 && c.roff >= c.readFailAt {
		return 0, errFault
	}
	if c.roff >= len(c.script) {
		return 0, errFault
	}
	limit := len(c.script)
	if c.readFailAt > 0 && c.readFailAt < limit {
		limit = c.readFailAt
	}
	n := copy(p, c.script[c.roff:limit])
	c.roff += n
	return n, nil
}

func (c *scriptConn) Write(p []byte) (int, error) {
	if c.writeFailNow {
		return 0, errFault
	}
	if c.writeFailAt > 0 && c.written >= c.writeFailAt {
		return 0, errFault
	}
	c.written += len(p)
	return len(p), nil
}

func (c *scriptConn) Close() error                       { return nil }
func (c *scriptConn) LocalAddr() net.Addr                { return nil }
func (c *scriptConn) RemoteAddr() net.Addr               { return nil }
func (c *scriptConn) SetDeadline(t time.Time) error      { return nil }
func (c *scriptConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *scriptConn) SetWriteDeadline(t time.Time) error { return nil }

func enc(t *testing.T, v interface{}) []byte {
	t.Helper()
	b := &bytes.Buffer{}
	if err := binary.Write(b, binary.BigEndian, v); err != nil {
		t.Fatalf("enc: %v", err)
	}
	return b.Bytes()
}

// serverHandshake returns the bytes a server sends to open a fixed-newstyle
// handshake.
func serverHandshake(t *testing.T) []byte {
	return enc(t, protocol.NegotiationNewstyleHeader{
		OldstyleMagic:  protocol.NEGOTIATION_MAGIC_OLDSTYLE,
		OptionMagic:    protocol.NEGOTIATION_MAGIC_OPTION,
		HandshakeFlags: protocol.NEGOTIATION_HANDSHAKE_FLAG_FIXED_NEWSTYLE,
	})
}

func replyHeader(t *testing.T, typ uint32, length uint32) []byte {
	return enc(t, protocol.NegotiationReplyHeader{
		ReplyMagic: protocol.NEGOTIATION_MAGIC_REPLY,
		ID:         protocol.NEGOTIATION_ID_OPTION_GO,
		Type:       typ,
		Length:     length,
	})
}

// TestNegotiateNewstyleClientFlagsWriteError covers the failed write of the
// client flags at the end of negotiateNewstyle: the handshake read succeeds but
// the very first write fails.
func TestNegotiateNewstyleClientFlagsWriteError(t *testing.T) {
	c := &scriptConn{script: serverHandshake(t), writeFailNow: true}
	if _, err := newDevice(c, Options{}); !errors.Is(err, errFault) {
		t.Fatalf("want errFault, got %v", err)
	}
}

// TestNegotiateGoWriteErrors covers each write step inside negotiateGo by
// failing the write after a growing number of bytes. The handshake itself
// needs 4 bytes (client flags) to succeed first.
func TestNegotiateGoWriteErrors(t *testing.T) {
	// Bytes the client writes during the GO negotiation after the 4-byte
	// client flags: 16-byte option header, 4-byte name length, name, 2-byte
	// info count. Failing at 4, 20, 24 and 24+len(name) exercises every write.
	name := "vol"
	for _, failAt := range []int{4, 20, 24, 24 + len(name)} {
		c := &scriptConn{script: serverHandshake(t), writeFailAt: failAt}
		if _, err := newDevice(c, Options{ExportName: name}); !errors.Is(err, errFault) {
			t.Fatalf("failAt=%d: want errFault, got %v", failAt, err)
		}
	}
}

// TestReadReplyHeaderError covers readReplyHeader's read-error branch: the
// handshake completes, the GO option is written, then the server stream ends
// before a reply header arrives.
func TestReadReplyHeaderError(t *testing.T) {
	c := &scriptConn{script: serverHandshake(t)}
	if _, err := newDevice(c, Options{}); !errors.Is(err, errFault) {
		t.Fatalf("want errFault, got %v", err)
	}
}

// TestNegotiateGoInfoReadError covers the io.ReadFull error while reading an
// NBD_INFO record body.
func TestNegotiateGoInfoReadError(t *testing.T) {
	script := append(serverHandshake(t), replyHeader(t, protocol.NEGOTIATION_TYPE_REPLY_INFO, 12)...)
	// Provide only 4 of the 12 promised info bytes, then EOF.
	script = append(script, 0, 0, 0, 0)
	c := &scriptConn{script: script}
	if _, err := newDevice(c, Options{}); !errors.Is(err, errFault) {
		t.Fatalf("want errFault, got %v", err)
	}
}

// TestNegotiateGoInfoExportShort covers the binary.Read error when an
// NBD_INFO_EXPORT record is announced with a length too small for the struct,
// driving both the binary.Read failure and the sliceReader EOF-after-data path.
func TestNegotiateGoInfoExportShort(t *testing.T) {
	// Length 4: enough to pass the <2 check and be read fully, but too short
	// for the 12-byte NegotiationReplyInfo, so binary.Read over the slice
	// hits EOF on its second Read.
	body := []byte{0, 0, 0, 0} // infoType 0 (EXPORT) + 2 extra bytes
	script := append(serverHandshake(t), replyHeader(t, protocol.NEGOTIATION_TYPE_REPLY_INFO, uint32(len(body)))...)
	script = append(script, body...)
	c := &scriptConn{script: script}
	if _, err := newDevice(c, Options{}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want io.ErrUnexpectedEOF, got %v", err)
	}
}

// TestNegotiateGoUnknownReplyType covers the default non-error reply branch
// returning ErrUnknownReply (e.g. an unexpected NBD_REP_SERVER).
func TestNegotiateGoUnknownReplyType(t *testing.T) {
	script := append(serverHandshake(t), replyHeader(t, protocol.NEGOTIATION_TYPE_REPLY_SERVER, 0)...)
	c := &scriptConn{script: script}
	if _, err := newDevice(c, Options{}); !errors.Is(err, ErrUnknownReply) {
		t.Fatalf("want ErrUnknownReply, got %v", err)
	}
}

// TestNegotiateGoErrDiscardErrors covers the io.CopyN discard-error branches
// for each error reply type (UNSUPPORTED, UNKNOWN, generic) when the server
// announces a payload length it does not deliver.
func TestNegotiateGoErrDiscardErrors(t *testing.T) {
	cases := []uint32{
		protocol.NEGOTIATION_TYPE_REPLY_ERR_UNSUPPORTED,
		protocol.NEGOTIATION_TYPE_REPLY_ERR_UNKNOWN,
		uint32(99) | uint32(1<<31),
	}
	for _, typ := range cases {
		script := append(serverHandshake(t), replyHeader(t, typ, 8)...) // promise 8, send 0
		c := &scriptConn{script: script}
		if _, err := newDevice(c, Options{}); !errors.Is(err, errFault) {
			t.Fatalf("typ=%#x: want errFault, got %v", typ, err)
		}
	}
}

// TestStartTLSWriteError covers the failed write of the STARTTLS option header.
func TestStartTLSWriteError(t *testing.T) {
	_, cliCfg := genTLSConfigs(t)
	c := &scriptConn{script: serverHandshake(t), writeFailAt: 4} // 4 = after client flags
	if _, err := newDevice(c, Options{TLS: cliCfg}); !errors.Is(err, errFault) {
		t.Fatalf("want errFault, got %v", err)
	}
}

// TestStartTLSReplyReadError covers the read-error branch when the reply header
// to STARTTLS never arrives.
func TestStartTLSReplyReadError(t *testing.T) {
	_, cliCfg := genTLSConfigs(t)
	c := &scriptConn{script: serverHandshake(t)} // nothing after handshake
	if _, err := newDevice(c, Options{TLS: cliCfg}); !errors.Is(err, errFault) {
		t.Fatalf("want errFault, got %v", err)
	}
}

// TestStartTLSDiscardError covers the io.CopyN discard-error branch when the
// STARTTLS reply announces a payload it does not deliver.
func TestStartTLSDiscardError(t *testing.T) {
	_, cliCfg := genTLSConfigs(t)
	hdr := enc(t, protocol.NegotiationReplyHeader{
		ReplyMagic: protocol.NEGOTIATION_MAGIC_REPLY,
		ID:         negotiationIDOptionStartTLS,
		Type:       protocol.NEGOTIATION_TYPE_REPLY_ACK,
		Length:     8, // promise 8 bytes, deliver none
	})
	c := &scriptConn{script: append(serverHandshake(t), hdr...)}
	if _, err := newDevice(c, Options{TLS: cliCfg}); !errors.Is(err, errFault) {
		t.Fatalf("want errFault, got %v", err)
	}
}

// TestExportNameWriteErrors covers the two write-error branches in
// negotiateExportName (option header and name) after a GO->UNSUPPORTED
// fallback.
func TestExportNameWriteErrors(t *testing.T) {
	// First the server must reject GO so the client falls back. Build a
	// script: handshake + GO ERR_UNSUPPORTED reply. Then the client writes the
	// EXPORT_NAME option header (16 bytes) + name. Fail writes at increasing
	// counts. Writes consumed before fallback: 4 (client flags) + 16 (GO
	// option header) + 4 (name length) + name + 2 (info count).
	name := "exp"
	base := 4 + 16 + 4 + len(name) + 2
	script := append(serverHandshake(t), replyHeader(t, protocol.NEGOTIATION_TYPE_REPLY_ERR_UNSUPPORTED, 0)...)
	for _, extra := range []int{0, 16} { // fail at option header, then at name
		c := &scriptConn{script: script, writeFailAt: base + extra}
		if _, err := newDevice(c, Options{ExportName: name}); !errors.Is(err, errFault) {
			t.Fatalf("extra=%d: want errFault, got %v", extra, err)
		}
	}
}

// TestExportNameReplyNonEOFError covers the non-EOF read-error branch of
// negotiateExportName (the reply read fails with a transport error rather than
// EOF).
func TestExportNameReplyNonEOFError(t *testing.T) {
	name := "exp"
	// handshake + GO ERR_UNSUPPORTED. The EXPORT_NAME reply read then fails
	// with errFault (a non-EOF error) because the script ends and scriptConn
	// returns errFault rather than io.EOF.
	script := append(serverHandshake(t), replyHeader(t, protocol.NEGOTIATION_TYPE_REPLY_ERR_UNSUPPORTED, 0)...)
	c := &scriptConn{script: script}
	if _, err := newDevice(c, Options{ExportName: name}); !errors.Is(err, errFault) {
		t.Fatalf("want errFault, got %v", err)
	}
}

// TestExportNamePaddingDiscardError covers the io.CopyN(124) discard-error
// branch: the server sends a valid size+flags but fewer than 124 padding
// bytes.
func TestExportNamePaddingDiscardError(t *testing.T) {
	name := "exp"
	script := append(serverHandshake(t), replyHeader(t, protocol.NEGOTIATION_TYPE_REPLY_ERR_UNSUPPORTED, 0)...)
	script = append(script, enc(t, uint64(1024))...) // size
	script = append(script, enc(t, uint16(0))...)    // flags
	script = append(script, make([]byte, 10)...)     // only 10 of 124 padding
	c := &scriptConn{script: script}
	if _, err := newDevice(c, Options{ExportName: name}); !errors.Is(err, errFault) {
		t.Fatalf("want errFault, got %v", err)
	}
}

// fullHandshakeScript builds a script that completes a GO handshake with the
// given flags and leaves the connection in transmission, so transact-level
// faults can be injected.
func fullHandshakeScript(t *testing.T, size uint64, flags uint16) []byte {
	t.Helper()
	info := enc(t, protocol.NegotiationReplyInfo{
		Type:              protocol.NEGOTIATION_TYPE_INFO_EXPORT,
		Size:              size,
		TransmissionFlags: flags,
	})
	s := serverHandshake(t)
	s = append(s, replyHeader(t, protocol.NEGOTIATION_TYPE_REPLY_INFO, uint32(len(info)))...)
	s = append(s, info...)
	s = append(s, replyHeader(t, protocol.NEGOTIATION_TYPE_REPLY_ACK, 0)...)
	return s
}

// TestTransactRequestWriteError covers the failed write of a request header.
func TestTransactRequestWriteError(t *testing.T) {
	script := fullHandshakeScript(t, 512, allFlags)
	// Writes during handshake: 4 (flags) + 16 (GO header) + 4 (namelen) +
	// 0 (empty name) + 2 (info count) = 26. Fail the next write (the request
	// header).
	c := &scriptConn{script: script, writeFailAt: 26}
	dev, err := newDevice(c, Options{})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if _, err := dev.ReadAt(make([]byte, 4), 0); !errors.Is(err, errFault) {
		t.Fatalf("want errFault, got %v", err)
	}
}

// TestTransactWriteDataError covers the failed write of the payload after the
// request header (a WRITE command).
func TestTransactWriteDataError(t *testing.T) {
	script := fullHandshakeScript(t, 512, allFlags)
	// 26 handshake bytes + 28-byte request header = 54; fail the data write.
	c := &scriptConn{script: script, writeFailAt: 54}
	dev, err := newDevice(c, Options{})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if _, err := dev.WriteAt([]byte{1, 2, 3, 4}, 0); !errors.Is(err, errFault) {
		t.Fatalf("want errFault, got %v", err)
	}
}

// TestTransactReplyReadError covers the failed read of the reply header.
func TestTransactReplyReadError(t *testing.T) {
	script := fullHandshakeScript(t, 512, allFlags)
	// No reply bytes after the handshake; the reply-header read fails.
	c := &scriptConn{script: script}
	dev, err := newDevice(c, Options{})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if _, err := dev.ReadAt(make([]byte, 4), 0); !errors.Is(err, errFault) {
		t.Fatalf("want errFault, got %v", err)
	}
}

// TestUnmapTransactError covers UnmapAt's propagation of a transact error.
func TestUnmapTransactError(t *testing.T) {
	script := fullHandshakeScript(t, 512, allFlags)
	c := &scriptConn{script: script} // no reply -> read fails
	dev, err := newDevice(c, Options{})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if _, err := dev.UnmapAt(4, 0); !errors.Is(err, errFault) {
		t.Fatalf("want errFault, got %v", err)
	}
}
