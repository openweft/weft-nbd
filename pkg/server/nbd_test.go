package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/openweft/weft-nbd/pkg/backend"
	"github.com/openweft/weft-nbd/pkg/protocol"
)

// syncBackend is a minimal backend.Backend (no UnmapAt) that records whether
// Sync was called and optionally returns an error from it. It does NOT
// implement TrimmableBackend, so the server must not advertise SEND_TRIM.
type syncBackend struct {
	mu      sync.Mutex
	data    []byte
	synced  int
	syncErr error
}

func newSyncBackend(size int) *syncBackend { return &syncBackend{data: make([]byte, size)} }

func (b *syncBackend) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b.data)) {
		return 0, io.EOF
	}
	return copy(p, b.data[off:]), nil
}

func (b *syncBackend) WriteAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b.data)) {
		return 0, io.EOF
	}
	return copy(b.data[off:], p), nil
}

func (b *syncBackend) Size() (int64, error) { return int64(len(b.data)), nil }

func (b *syncBackend) Sync() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.synced++
	return b.syncErr
}

func (b *syncBackend) syncCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.synced
}

// trimBackend additionally implements TrimmableBackend, recording UnmapAt
// invocations. The server must advertise SEND_TRIM for it.
type trimBackend struct {
	syncBackend
	umu         sync.Mutex
	unmapLen    uint32
	unmapOff    int64
	unmapCalled int
	unmapErr    error
}

func newTrimBackend(size int) *trimBackend {
	return &trimBackend{syncBackend: syncBackend{data: make([]byte, size)}}
}

func (b *trimBackend) UnmapAt(length uint32, off int64) (int, error) {
	b.umu.Lock()
	defer b.umu.Unlock()
	b.unmapCalled++
	b.unmapLen = length
	b.unmapOff = off
	if b.unmapErr != nil {
		return 0, b.unmapErr
	}
	return int(length), nil
}

func (b *trimBackend) unmapInfo() (int, uint32, int64) {
	b.umu.Lock()
	defer b.umu.Unlock()
	return b.unmapCalled, b.unmapLen, b.unmapOff
}

// Compile-time assertions that the test backends have the intended shapes.
var (
	_ backend.Backend  = (*syncBackend)(nil)
	_ backend.Backend  = (*trimBackend)(nil)
	_ TrimmableBackend = (*trimBackend)(nil)
)

// testClient is a tiny NBD client used to drive Handle over a net.Pipe. It
// negotiates a single export via NBD_OPT_GO and then issues raw transmission
// requests, returning the negotiated transmission flags.
type testClient struct {
	t     *testing.T
	conn  net.Conn
	flags uint16
}

// handshake runs the server-side Handle in a goroutine and performs the
// client-side fixed-newstyle + NBD_OPT_GO handshake, returning the connected
// testClient plus a channel that yields Handle's return error.
func handshake(t *testing.T, exports []*Export, options *Options, exportName string) (*testClient, <-chan error) {
	t.Helper()

	serverConn, clientConn := net.Pipe()

	errCh := make(chan error, 1)
	go func() { errCh <- Handle(serverConn, exports, options) }()

	c := &testClient{t: t, conn: clientConn}
	c.negotiateGo(exportName)
	return c, errCh
}

func (c *testClient) negotiateGo(exportName string) {
	c.t.Helper()

	var hdr protocol.NegotiationNewstyleHeader
	if err := binary.Read(c.conn, binary.BigEndian, &hdr); err != nil {
		c.t.Fatalf("read newstyle header: %v", err)
	}
	if hdr.OldstyleMagic != protocol.NEGOTIATION_MAGIC_OLDSTYLE || hdr.OptionMagic != protocol.NEGOTIATION_MAGIC_OPTION {
		c.t.Fatalf("bad handshake magics")
	}

	// Client flags.
	if err := binary.Write(c.conn, binary.BigEndian, uint32(protocol.NEGOTIATION_HANDSHAKE_FLAG_FIXED_NEWSTYLE)); err != nil {
		c.t.Fatalf("write client flags: %v", err)
	}

	name := []byte(exportName)
	payloadLen := uint32(4 + len(name) + 2)
	if err := binary.Write(c.conn, binary.BigEndian, protocol.NegotiationOptionHeader{
		OptionMagic: protocol.NEGOTIATION_MAGIC_OPTION,
		ID:          protocol.NEGOTIATION_ID_OPTION_GO,
		Length:      payloadLen,
	}); err != nil {
		c.t.Fatalf("write option header: %v", err)
	}
	if err := binary.Write(c.conn, binary.BigEndian, uint32(len(name))); err != nil {
		c.t.Fatalf("write name length: %v", err)
	}
	if _, err := c.conn.Write(name); err != nil {
		c.t.Fatalf("write name: %v", err)
	}
	if err := binary.Write(c.conn, binary.BigEndian, uint16(0)); err != nil {
		c.t.Fatalf("write info request count: %v", err)
	}

	for {
		var reply protocol.NegotiationReplyHeader
		if err := binary.Read(c.conn, binary.BigEndian, &reply); err != nil {
			c.t.Fatalf("read reply header: %v", err)
		}
		if reply.ReplyMagic != protocol.NEGOTIATION_MAGIC_REPLY {
			c.t.Fatalf("bad reply magic")
		}

		body := make([]byte, reply.Length)
		if _, err := io.ReadFull(c.conn, body); err != nil {
			c.t.Fatalf("read reply body: %v", err)
		}

		switch reply.Type {
		case protocol.NEGOTIATION_TYPE_REPLY_INFO:
			if len(body) >= 2 && binary.BigEndian.Uint16(body[:2]) == protocol.NEGOTIATION_TYPE_INFO_EXPORT {
				var info protocol.NegotiationReplyInfo
				if err := binary.Read(bytes.NewReader(body), binary.BigEndian, &info); err != nil {
					c.t.Fatalf("decode export info: %v", err)
				}
				c.flags = info.TransmissionFlags
			}
		case protocol.NEGOTIATION_TYPE_REPLY_ACK:
			return
		case protocol.NEGOTIATION_TYPE_REPLY_ERR_UNKNOWN:
			c.t.Fatalf("export not found")
		default:
			c.t.Fatalf("unexpected reply type 0x%x", reply.Type)
		}
	}
}

// command sends a transmission request (optionally with data) and reads the
// simple reply header, returning the reply error code. readLen bytes of reply
// payload are consumed (and discarded) when non-zero.
func (c *testClient) command(reqType uint16, off uint64, length uint32, data []byte, readLen int) uint32 {
	c.t.Helper()

	if err := binary.Write(c.conn, binary.BigEndian, protocol.TransmissionRequestHeader{
		RequestMagic: protocol.TRANSMISSION_MAGIC_REQUEST,
		Type:         reqType,
		Handle:       0x1234,
		Offset:       off,
		Length:       length,
	}); err != nil {
		c.t.Fatalf("write request header: %v", err)
	}
	if data != nil {
		if _, err := c.conn.Write(data); err != nil {
			c.t.Fatalf("write data: %v", err)
		}
	}

	var reply protocol.TransmissionReplyHeader
	if err := binary.Read(c.conn, binary.BigEndian, &reply); err != nil {
		c.t.Fatalf("read reply: %v", err)
	}
	if reply.ReplyMagic != protocol.TRANSMISSION_MAGIC_REPLY {
		c.t.Fatalf("bad reply magic")
	}
	if reply.Handle != 0x1234 {
		c.t.Fatalf("handle mismatch: %x", reply.Handle)
	}
	if readLen > 0 {
		if _, err := io.CopyN(io.Discard, c.conn, int64(readLen)); err != nil {
			c.t.Fatalf("discard reply payload: %v", err)
		}
	}
	return reply.Error
}

// disconnect sends NBD_CMD_DISC and waits for Handle to return nil.
func (c *testClient) disconnect(errCh <-chan error) {
	c.t.Helper()

	if err := binary.Write(c.conn, binary.BigEndian, protocol.TransmissionRequestHeader{
		RequestMagic: protocol.TRANSMISSION_MAGIC_REQUEST,
		Type:         protocol.TRANSMISSION_TYPE_REQUEST_DISC,
	}); err != nil {
		c.t.Fatalf("write disc: %v", err)
	}
	if err := <-errCh; err != nil {
		c.t.Fatalf("Handle returned error: %v", err)
	}
	c.conn.Close()
}

func TestFlushAdvertisedAndDispatched(t *testing.T) {
	be := newSyncBackend(512)
	exports := []*Export{{Name: "default", Backend: be}}

	c, errCh := handshake(t, exports, &Options{SupportsMultiConn: true}, "default")

	if c.flags&protocol.NEGOTIATION_REPLY_FLAGS_HAS_FLAGS == 0 {
		t.Fatalf("HAS_FLAGS not advertised: 0x%x", c.flags)
	}
	if c.flags&protocol.TRANSMISSION_FLAG_SEND_FLUSH == 0 {
		t.Fatalf("SEND_FLUSH not advertised: 0x%x", c.flags)
	}
	if c.flags&protocol.NEGOTIATION_REPLY_FLAGS_CAN_MULTI_CONN == 0 {
		t.Fatalf("CAN_MULTI_CONN not advertised: 0x%x", c.flags)
	}
	if c.flags&protocol.TRANSMISSION_FLAG_SEND_TRIM != 0 {
		t.Fatalf("SEND_TRIM advertised for non-trimmable backend: 0x%x", c.flags)
	}
	if c.flags&protocol.TRANSMISSION_FLAG_READ_ONLY != 0 {
		t.Fatalf("READ_ONLY advertised for writable export: 0x%x", c.flags)
	}

	if errCode := c.command(protocol.TRANSMISSION_TYPE_REQUEST_FLUSH, 0, 0, nil, 0); errCode != 0 {
		t.Fatalf("FLUSH returned error code %d", errCode)
	}
	if got := be.syncCount(); got != 1 {
		t.Fatalf("Sync called %d times, want 1", got)
	}

	c.disconnect(errCh)
}

func TestFlushSyncError(t *testing.T) {
	be := newSyncBackend(512)
	be.syncErr = errors.New("disk on fire")
	exports := []*Export{{Name: "default", Backend: be}}

	// Read-only so the DISC at teardown does not also invoke the failing Sync
	// (only FLUSH should exercise the error path here).
	c, errCh := handshake(t, exports, &Options{ReadOnly: true}, "default")

	errCode := c.command(protocol.TRANSMISSION_TYPE_REQUEST_FLUSH, 0, 0, nil, 0)
	if errCode != protocol.TRANSMISSION_ERROR_EIO {
		t.Fatalf("FLUSH error code = %d, want EIO (%d)", errCode, protocol.TRANSMISSION_ERROR_EIO)
	}
	if got := be.syncCount(); got != 1 {
		t.Fatalf("Sync called %d times, want 1", got)
	}

	// The connection is still usable: disconnect cleanly.
	c.disconnect(errCh)
}

func TestTrimAdvertisedAndDispatched(t *testing.T) {
	be := newTrimBackend(512)
	exports := []*Export{{Name: "default", Backend: be}}

	c, errCh := handshake(t, exports, &Options{}, "default")

	if c.flags&protocol.TRANSMISSION_FLAG_SEND_TRIM == 0 {
		t.Fatalf("SEND_TRIM not advertised for trimmable backend: 0x%x", c.flags)
	}

	if errCode := c.command(protocol.TRANSMISSION_TYPE_REQUEST_TRIM, 64, 128, nil, 0); errCode != 0 {
		t.Fatalf("TRIM returned error code %d", errCode)
	}

	called, gotLen, gotOff := be.unmapInfo()
	if called != 1 {
		t.Fatalf("UnmapAt called %d times, want 1", called)
	}
	if gotLen != 128 || gotOff != 64 {
		t.Fatalf("UnmapAt(length=%d, off=%d), want (128, 64)", gotLen, gotOff)
	}

	c.disconnect(errCh)
}

func TestTrimError(t *testing.T) {
	be := newTrimBackend(512)
	be.unmapErr = errors.New("unmap failed")
	exports := []*Export{{Name: "default", Backend: be}}

	c, errCh := handshake(t, exports, &Options{}, "default")

	// Send TRIM; the server propagates the UnmapAt error by returning from
	// Handle, which tears down the pipe.
	if err := binary.Write(c.conn, binary.BigEndian, protocol.TransmissionRequestHeader{
		RequestMagic: protocol.TRANSMISSION_MAGIC_REQUEST,
		Type:         protocol.TRANSMISSION_TYPE_REQUEST_TRIM,
		Handle:       0x1234,
		Offset:       0,
		Length:       16,
	}); err != nil {
		t.Fatalf("write trim: %v", err)
	}

	if err := <-errCh; err == nil {
		t.Fatalf("Handle returned nil, want UnmapAt error")
	}
	c.conn.Close()
}

func TestTrimNoOpOnNonTrimmableBackend(t *testing.T) {
	be := newSyncBackend(512)
	exports := []*Export{{Name: "default", Backend: be}}

	c, errCh := handshake(t, exports, &Options{}, "default")

	if c.flags&protocol.TRANSMISSION_FLAG_SEND_TRIM != 0 {
		t.Fatalf("SEND_TRIM advertised for non-trimmable backend: 0x%x", c.flags)
	}

	// A misbehaving client may still send TRIM; the server treats it as a
	// successful no-op (zero-length reply, error 0).
	if errCode := c.command(protocol.TRANSMISSION_TYPE_REQUEST_TRIM, 0, 32, nil, 0); errCode != 0 {
		t.Fatalf("TRIM no-op returned error code %d", errCode)
	}

	c.disconnect(errCh)
}

// failAfterConn wraps a net.Conn and starts returning errFailWrite from Write
// once armed. It lets a test exercise the reply-write error branches: the
// handshake runs over the real pipe, then writes are made to fail before the
// server emits a FLUSH/TRIM reply.
type failAfterConn struct {
	net.Conn
	mu    sync.Mutex
	armed bool
}

var errFailWrite = errors.New("injected write failure")

func (c *failAfterConn) arm() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.armed = true
}

func (c *failAfterConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	armed := c.armed
	c.mu.Unlock()
	if armed {
		return 0, errFailWrite
	}
	return c.Conn.Write(p)
}

// handshakeFailConn is like handshake but interposes a failAfterConn on the
// server side and returns it so the test can arm write failures after the
// handshake completes.
func handshakeFailConn(t *testing.T, exports []*Export, options *Options) (*testClient, *failAfterConn, <-chan error) {
	t.Helper()

	rawServer, clientConn := net.Pipe()
	fc := &failAfterConn{Conn: rawServer}

	errCh := make(chan error, 1)
	go func() { errCh <- Handle(fc, exports, options) }()

	c := &testClient{t: t, conn: clientConn}
	c.negotiateGo("default")
	return c, fc, errCh
}

func TestFlushReplyWriteError(t *testing.T) {
	be := newSyncBackend(512)
	exports := []*Export{{Name: "default", Backend: be}}

	c, fc, errCh := handshakeFailConn(t, exports, &Options{})

	fc.arm()
	if err := binary.Write(c.conn, binary.BigEndian, protocol.TransmissionRequestHeader{
		RequestMagic: protocol.TRANSMISSION_MAGIC_REQUEST,
		Type:         protocol.TRANSMISSION_TYPE_REQUEST_FLUSH,
	}); err != nil {
		t.Fatalf("write flush: %v", err)
	}

	if err := <-errCh; !errors.Is(err, errFailWrite) {
		t.Fatalf("Handle error = %v, want injected write failure", err)
	}
	c.conn.Close()
}

func TestTrimReplyWriteError(t *testing.T) {
	be := newTrimBackend(512)
	exports := []*Export{{Name: "default", Backend: be}}

	c, fc, errCh := handshakeFailConn(t, exports, &Options{})

	fc.arm()
	if err := binary.Write(c.conn, binary.BigEndian, protocol.TransmissionRequestHeader{
		RequestMagic: protocol.TRANSMISSION_MAGIC_REQUEST,
		Type:         protocol.TRANSMISSION_TYPE_REQUEST_TRIM,
		Length:       16,
	}); err != nil {
		t.Fatalf("write trim: %v", err)
	}

	if err := <-errCh; !errors.Is(err, errFailWrite) {
		t.Fatalf("Handle error = %v, want injected write failure", err)
	}
	c.conn.Close()
}

func TestReadOnlyAdvertised(t *testing.T) {
	be := newSyncBackend(512)
	exports := []*Export{{Name: "default", Backend: be}}

	c, errCh := handshake(t, exports, &Options{ReadOnly: true}, "default")

	if c.flags&protocol.TRANSMISSION_FLAG_READ_ONLY == 0 {
		t.Fatalf("READ_ONLY not advertised for read-only export: 0x%x", c.flags)
	}
	// SEND_FLUSH is still advertised on a read-only export.
	if c.flags&protocol.TRANSMISSION_FLAG_SEND_FLUSH == 0 {
		t.Fatalf("SEND_FLUSH not advertised on read-only export: 0x%x", c.flags)
	}

	// DISC on a read-only export must not call Sync.
	if err := binary.Write(c.conn, binary.BigEndian, protocol.TransmissionRequestHeader{
		RequestMagic: protocol.TRANSMISSION_MAGIC_REQUEST,
		Type:         protocol.TRANSMISSION_TYPE_REQUEST_DISC,
	}); err != nil {
		t.Fatalf("write disc: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if got := be.syncCount(); got != 0 {
		t.Fatalf("Sync called %d times on read-only DISC, want 0", got)
	}
	c.conn.Close()
}
