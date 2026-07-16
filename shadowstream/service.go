package shadowstream

import (
	"context"
	"crypto/cipher"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/metacubex/sing-shadowsocks"
	"github.com/metacubex/sing/common/buf"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/metacubex/sing/common/udpnat"
)

var _ shadowsocks.Service = (*Service)(nil)

type Service struct {
	*Method
	password string
	handler  shadowsocks.Handler
	udpNat   *udpnat.Service[netip.AddrPort]
}

func NewService(method string, key []byte, password string, udpTimeout int64, handler shadowsocks.Handler) (*Service, error) {
	methodInstance, err := New(method, key, password)
	if err != nil {
		return nil, err
	}
	s := &Service{
		Method:   methodInstance,
		password: password,
		handler:  handler,
		udpNat:   udpnat.New[netip.AddrPort](udpTimeout, handler),
	}
	return s, nil
}

func (s *Service) Name() string {
	return s.name
}

func (s *Service) Password() string {
	return s.password
}

func (s *Service) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	err := s.newConnection(ctx, conn, metadata)
	if err != nil {
		err = &shadowsocks.ServerConnError{Conn: conn, Source: metadata.Source, Cause: err}
	}
	return err
}

func (s *Service) newConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	salt := buf.NewSize(s.saltLength)
	defer salt.Release()

	_, err := salt.ReadFullFrom(conn, s.saltLength)
	if err != nil {
		return E.Cause(err, "read salt")
	}
	readStream, err := s.decryptConstructor(s.key, salt.Bytes())
	if err != nil {
		return err
	}

	serverConn := &serverConn{
		Method:     s.Method,
		Conn:       conn,
		readStream: readStream,
	}
	destination, err := M.SocksaddrSerializer.ReadAddrPort(serverConn)
	if err != nil {
		return err
	}

	metadata.Protocol = "shadowsocks"
	metadata.Destination = destination
	return s.handler.NewConnection(ctx, serverConn, metadata)
}

func (s *Service) NewError(ctx context.Context, err error) {
	s.handler.NewError(ctx, err)
}

type serverConn struct {
	*Method
	net.Conn
	access      sync.Mutex
	readStream  cipher.Stream
	writeStream cipher.Stream
}

func (c *serverConn) Read(p []byte) (n int, err error) {
	n, err = c.Conn.Read(p)
	if n > 0 {
		c.readStream.XORKeyStream(p[:n], p[:n])
	}
	return
}

func (c *serverConn) Write(p []byte) (n int, err error) {
	if c.writeStream != nil {
		return c.writeEncrypted(p)
	}
	c.access.Lock()
	defer c.access.Unlock()
	if c.writeStream != nil {
		return c.writeEncrypted(p)
	}

	buffer := buf.NewSize(c.saltLength + len(p))
	defer buffer.Release()
	salt := buffer.WriteRandom(c.saltLength)
	writeStream, err := c.encryptConstructor(c.key, salt)
	if err != nil {
		return 0, err
	}
	writeStream.XORKeyStream(buffer.Extend(len(p)), p)
	writeN, err := c.Conn.Write(buffer.Bytes())
	if err == nil && writeN != buffer.Len() {
		err = io.ErrShortWrite
	}
	if writeN > c.saltLength {
		n = writeN - c.saltLength
		if n > len(p) {
			n = len(p)
		}
	}
	if err == nil {
		c.writeStream = writeStream
	}
	return
}

func (c *serverConn) writeEncrypted(p []byte) (n int, err error) {
	buffer := buf.NewSize(len(p))
	defer buffer.Release()
	c.writeStream.XORKeyStream(buffer.Extend(len(p)), p)
	n, err = c.Conn.Write(buffer.Bytes())
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return
}

func (c *serverConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *serverConn) Upstream() any {
	return c.Conn
}

func (s *Service) WriteIsThreadUnsafe() {
}

func (s *Service) NewPacket(ctx context.Context, conn N.PacketConn, buffer *buf.Buffer, metadata M.Metadata) error {
	err := s.newPacket(ctx, conn, buffer, metadata)
	if err != nil {
		err = &shadowsocks.ServerPacketError{Source: metadata.Source, Cause: err}
	}
	return err
}

func (s *Service) newPacket(ctx context.Context, conn N.PacketConn, buffer *buf.Buffer, metadata M.Metadata) error {
	if buffer.Len() < s.saltLength {
		return io.ErrShortBuffer
	}
	readStream, err := s.decryptConstructor(s.key, buffer.To(s.saltLength))
	if err != nil {
		return err
	}
	readStream.XORKeyStream(buffer.From(s.saltLength), buffer.From(s.saltLength))
	buffer.Advance(s.saltLength)

	destination, err := M.SocksaddrSerializer.ReadAddrPort(buffer)
	if err != nil {
		return err
	}

	metadata.Protocol = "shadowsocks"
	metadata.Destination = destination
	s.udpNat.NewPacket(ctx, metadata.Source.AddrPort(), buffer, metadata, func(natConn N.PacketConn) N.PacketWriter {
		return &serverPacketWriter{s.Method, conn, natConn}
	})
	return nil
}

type serverPacketWriter struct {
	*Method
	source N.PacketConn
	nat    N.PacketConn
}

func (w *serverPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	header := buf.With(buffer.ExtendHeader(w.saltLength + M.SocksaddrSerializer.AddrPortLen(destination)))
	salt := header.WriteRandom(w.saltLength)
	err := M.SocksaddrSerializer.WriteAddrPort(header, destination)
	if err != nil {
		buffer.Release()
		return err
	}
	writeStream, err := w.encryptConstructor(w.key, salt)
	if err != nil {
		buffer.Release()
		return err
	}
	writeStream.XORKeyStream(buffer.From(w.saltLength), buffer.From(w.saltLength))
	return w.source.WritePacket(buffer, M.SocksaddrFromNet(w.nat.LocalAddr()))
}

func (w *serverPacketWriter) FrontHeadroom() int {
	return w.saltLength + M.MaxSocksaddrLength
}

func (w *serverPacketWriter) Upstream() any {
	return w.source
}

func (w *serverPacketWriter) WriteIsThreadUnsafe() {
}
