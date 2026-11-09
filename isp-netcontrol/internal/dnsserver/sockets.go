package dnsserver

import (
	"context"
	"net"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// udpSocketsPerAddr is how many UDP sockets share each listen address.
func udpSocketsPerAddr() int {
	n := runtime.NumCPU()
	if n > 16 {
		n = 16
	}
	return n
}

// listenUDP opens several SO_REUSEPORT sockets on addr. If the option is not
// available it falls back to a single socket. Port 0 always gets one socket
// (each would otherwise get a different port).
func listenUDP(addr string) ([]net.PacketConn, error) {
	n := udpSocketsPerAddr()
	if strings.HasSuffix(addr, ":0") {
		n = 1
	}
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1) }); err != nil {
			return err
		}
		return serr
	}}
	first, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		// No SO_REUSEPORT (or another error): one plain socket.
		pc, err2 := net.ListenPacket("udp", addr)
		if err2 != nil {
			return nil, err2
		}
		return []net.PacketConn{pc}, nil
	}
	out := []net.PacketConn{first}
	for i := 1; i < n; i++ {
		pc, err := lc.ListenPacket(context.Background(), "udp", addr)
		if err != nil {
			break // keep what we have
		}
		out = append(out, pc)
	}
	return out, nil
}
