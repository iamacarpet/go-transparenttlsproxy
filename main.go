package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

func main() {
	l, err := net.Listen("tcp", "0.0.0.0:3143")
	if err != nil {
		panic(err)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			panic(err)
		}

		go func(c *net.TCPConn) {
			defer c.Close()

			remoteIP := c.RemoteAddr().(*net.TCPAddr).IP

			connUUID := uuid.New().String()

			br := bufio.NewReader(c)

			sni := clientHelloServerName(br)
			if sni == "" {
				log.Printf("%s SNI_TRANSPARENT/500 CONNECT %s UNKNOWN - SNI_FAIL/NONE", remoteIP, connUUID)
				return
			}

			addr, err := net.LookupHost(sni)
			if err != nil {
				log.Printf("%s SNI_TRANSPARENT/500 CONNECT %s %s - DNS_FAIL/%s", remoteIP, connUUID, sni+":443", err)
				return
			} else if len(addr) < 1 {
				log.Printf("%s SNI_TRANSPARENT/500 CONNECT %s %s - DNS_FAIL/NONE", remoteIP, connUUID, sni+":443")
				return
			} else if aclDeny(addr[0]) {
				log.Printf("%s SNI_TRANSPARENT/403 CONNECT %s %s - ACL_DENY/%s", remoteIP, connUUID, sni+":443", addr[0])
				return
			}

			backend, err := net.DialTimeout("tcp", addr[0]+":443", 10*time.Second)
			if err != nil {
				log.Printf("%s SNI_TRANSPARENT/500 CONNECT %s %s - CONN_FAIL/%s", remoteIP, connUUID, sni+":443", addr[0])
				return
			}
			defer backend.Close()

			var cp *Conn
			if n := br.Buffered(); n > 0 {
				peeked, _ := br.Peek(br.Buffered())
				cp = &Conn{
					Peeked: peeked,
					Conn:   c,
				}
			} else {
				cp = &Conn{
					Conn: c,
				}
			}
			bp := &Conn{
				Conn: backend,
			}

			var wg sync.WaitGroup
			wg.Add(2)
			go proxy(&wg, cp, bp)
			go proxy(&wg, bp, cp)
			log.Printf("%s SNI_TRANSPARENT/200 CONNECT %s %s - SNI_DIRECT/%s", remoteIP, connUUID, sni+":443", addr[0])
			wg.Wait()
			log.Printf("%s SNI_TRANSPARENT/200 CLOSE   %s %s - SNI_DIRECT/%s", remoteIP, connUUID, sni+":443", addr[0])
		}(c.(*net.TCPConn))
	}
}

// Conn is an incoming connection that has had some bytes read from it
// to determine how to route the connection. The Read method stitches
// the peeked bytes and unread bytes back together.
type Conn struct {
	// Peeked are the bytes that have been read from Conn for the
	// purposes of route matching, but have not yet been consumed
	// by Read calls. It set to nil by Read when fully consumed.
	Peeked []byte

	// Conn is the underlying connection.
	// It can be type asserted against *net.TCPConn or other types
	// as needed. It should not be read from directly unless
	// Peeked is nil.
	net.Conn
}

func (c *Conn) Read(p []byte) (n int, err error) {
	if len(c.Peeked) > 0 {
		n = copy(p, c.Peeked)
		c.Peeked = c.Peeked[n:]
		if len(c.Peeked) == 0 {
			c.Peeked = nil
		}
		return n, nil
	}
	return c.Conn.Read(p)
}

func proxy(wg *sync.WaitGroup, a, b *Conn) {
	defer wg.Done()
	atcp, btcp := a.Conn.(*net.TCPConn), b.Conn.(*net.TCPConn)
	if _, err := io.Copy(atcp, b); err != nil {
		//		log.Printf("%s<>%s -> %s<>%s: %s", atcp.RemoteAddr(), atcp.LocalAddr(), btcp.LocalAddr(), btcp.RemoteAddr(), err)
	}
	btcp.CloseWrite()
	atcp.CloseRead()
}

func clientHelloServerName(br *bufio.Reader) (sni string) {
	const recordHeaderLen = 5
	hdr, err := br.Peek(recordHeaderLen)
	if err != nil {
		return ""
	}
	const recordTypeHandshake = 0x16
	if hdr[0] != recordTypeHandshake {
		return "" // Not TLS.
	}
	recLen := int(hdr[3])<<8 | int(hdr[4]) // ignoring version in hdr[1:3]
	helloBytes, err := br.Peek(recordHeaderLen + recLen)
	if err != nil {
		return ""
	}
	tls.Server(sniSniffConn{r: bytes.NewReader(helloBytes)}, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = hello.ServerName
			return nil, nil
		},
	}).Handshake()
	return
}

func aclDeny(addr string) bool {
	blockedIPs := []string{"10.0.0.0/8"}

	ip := net.ParseIP(addr)

	for _, v := range blockedIPs {
		v = strings.TrimSpace(v)
		cIP, cIPNet, err := net.ParseCIDR(v)
		if err != nil {
			cIP = net.ParseIP(v)
			if cIP != nil {
				if cIP.Equal(ip) {
					return true
				}
			}
		} else {
			if cIPNet.Contains(ip) {
				return true
			}
		}
	}

	return false
}

type sniSniffConn struct {
	r        io.Reader
	net.Conn // nil; crash on any unexpected use
}

func (c sniSniffConn) Read(p []byte) (int, error) { return c.r.Read(p) }
func (sniSniffConn) Write(p []byte) (int, error)  { return 0, io.EOF }
