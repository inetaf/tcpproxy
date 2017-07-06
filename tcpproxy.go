// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package tcpproxy lets users build TCP proxies, optionally making
// routing decisions based on HTTP/1 Host headers and the SNI hostname
// in TLS connections.
//
// Typical usage:
//
//     var p tcpproxy.Proxy
//     p.AddHTTPHostRoute(":80", "foo.com", tcpproxy.To("10.0.0.1:8081"))
//     p.AddHTTPHostRoute(":80", "bar.com", tcpproxy.To("10.0.0.2:8082"))
//     p.AddRoute(":80", tcpproxy.To("10.0.0.1:8081")) // fallback
//     p.AddSNIRoute(":443", "foo.com", tcpproxy.To("10.0.0.1:4431"))
//     p.AddSNIRoute(":443", "bar.com", tcpproxy.To("10.0.0.2:4432"))
//     p.AddRoute(":443", tcpproxy.To("10.0.0.1:4431")) // fallback
//     log.Fatal(p.Run())
//
// Calling Run (or Start) on a proxy also starts all the necessary
// listeners.
//
// For each accepted connection, the rules for that ipPort are
// matched, in order. If one matches (currently HTTP Host, SNI, or
// always), then the connection is handed to the target.
//
// The two predefined Target implementations are:
//
// 1) DialProxy, proxying to another address (use the To func to return a
// DialProxy value),
//
// 2) TargetListener, making the matched connection available via a
// net.Listener.Accept call.
//
// But Target is an interface, so you can also write your own.
//
// Note that tcpproxy does not do any TLS encryption or decryption. It
// only (via DialProxy) copies bytes around. The SNI hostname in the TLS
// header is unencrypted, for better or worse.
//
// This package makes no API stability promises. If you depend on it,
// vendor it.
package tcpproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"time"
)

// Proxy is a proxy. Its zero value is a valid proxy that does
// nothing. Call methods to add routes before calling Start or Run.
//
// The order that routes are added in matters; each is matched in the order
// registered.
type Proxy struct {
	routes map[string][]route // ip:port => route

	lns   []net.Listener
	donec chan struct{} // closed before err
	err   error         // any error from listening

	// ListenFunc optionally specifies an alternate listen
	// function. If nil, net.Dial is used.
	// The provided net is always "tcp".
	ListenFunc func(net, laddr string) (net.Listener, error)
}

type route struct {
	matcher matcher
	target  Target
}

type matcher interface {
	match(*bufio.Reader) bool
}

func (p *Proxy) netListen() func(net, laddr string) (net.Listener, error) {
	if p.ListenFunc != nil {
		return p.ListenFunc
	}
	return net.Listen
}

func (p *Proxy) addRoute(ipPort string, matcher matcher, dest Target) {
	if p.routes == nil {
		p.routes = make(map[string][]route)
	}
	p.routes[ipPort] = append(p.routes[ipPort], route{matcher, dest})
}

// AddRoute appends an always-matching route to the ipPort listener,
// directing any connection to dest.
//
// This is generally used as either the only rule (for simple TCP
// proxies), or as the final fallback rule for an ipPort.
//
// The ipPort is any valid net.Listen TCP address.
func (p *Proxy) AddRoute(ipPort string, dest Target) {
	p.addRoute(ipPort, alwaysMatch{}, dest)
}

type alwaysMatch struct{}

func (alwaysMatch) match(*bufio.Reader) bool { return true }

// Run is calls Start, and then Wait.
//
// It blocks until there's an error. The return value is always
// non-nil.
func (p *Proxy) Run() error {
	if err := p.Start(); err != nil {
		return err
	}
	return p.Wait()
}

// Wait waits for the Proxy to finish running. Currently this can only
// happen if a Listener is closed, or Close is called on the proxy.
//
// It is only valid to call Wait after a successful call to Start.
func (p *Proxy) Wait() error {
	<-p.donec
	return p.err
}

// Close closes all the proxy's self-opened listeners.
func (p *Proxy) Close() error {
	for _, c := range p.lns {
		c.Close()
	}
	return nil
}

// Start creates a TCP listener for each unique ipPort from the
// previously created routes and starts the proxy. It returns any
// error from starting listeners.
//
// If it returns a non-nil error, any successfully opened listeners
// are closed.
func (p *Proxy) Start() error {
	if p.donec != nil {
		return errors.New("already started")
	}
	p.donec = make(chan struct{})
	errc := make(chan error, len(p.routes))
	p.lns = make([]net.Listener, 0, len(p.routes))
	for ipPort, routes := range p.routes {
		ln, err := p.netListen()("tcp", ipPort)
		if err != nil {
			p.Close()
			return err
		}
		p.lns = append(p.lns, ln)
		go p.serveListener(errc, ln, routes)
	}
	go p.awaitFirstError(errc)
	return nil
}

func (p *Proxy) awaitFirstError(errc <-chan error) {
	p.err = <-errc
	close(p.donec)
}

func (p *Proxy) serveListener(ret chan<- error, ln net.Listener, routes []route) {
	for {
		c, err := ln.Accept()
		if err != nil {
			ret <- err
			return
		}
		go p.serveConn(c, routes)
	}
}

// serveConn runs in its own goroutine and matches c against routes.
// It returns whether it matched purely for testing.
func (p *Proxy) serveConn(c net.Conn, routes []route) bool {
	br := bufio.NewReader(c)
	for _, route := range routes {
		if route.matcher.match(br) {
			if n := br.Buffered(); n > 0 {
				peeked, _ := br.Peek(br.Buffered())
				c = &Conn{
					Peeked: peeked,
					Conn:   c,
				}
			}
			route.target.HandleConn(c)
			return true
		}
	}
	// TODO: hook for this?
	log.Printf("tcpproxy: no routes matched conn %v/%v; closing", c.RemoteAddr().String(), c.LocalAddr().String())
	c.Close()
	return false
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

// Target is what an incoming matched connection is sent to.
type Target interface {
	// HandleConn is called when an incoming connection is
	// matched. After the call to HandleConn, the tcpproxy
	// package never touches the conn again. Implementations are
	// responsible for closing the connection when needed.
	//
	// The concrete type of conn will be of type *Conn if any
	// bytes have been consumed for the purposes of route
	// matching.
	HandleConn(net.Conn)
}

// To is shorthand way of writing &tlsproxy.DialProxy{Addr: addr}.
func To(addr string) *DialProxy {
	return &DialProxy{Addr: addr}
}

// DialProxy implements Target by dialing a new connection to Addr
// and then proxying data back and forth.
//
// The To func is a shorthand way of creating a DialProxy.
type DialProxy struct {
	// Addr is the TCP address to proxy to.
	Addr string

	// KeepAlivePeriod sets the period between TCP keep alives.
	// If zero, a default is used. To disable, use a negative number.
	// The keep-alive is used for both the client connection and
	KeepAlivePeriod time.Duration

	// DialTimeout optionally specifies a dial timeout.
	// If zero, a default is used.
	// If negative, the timeout is disabled.
	DialTimeout time.Duration

	// DialContext optionally specifies an alternate dial function
	// for TCP targets. If nil, the standard
	// net.Dialer.DialContext method is used.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)

	// OnDialError optionally specifies an alternate way to handle errors dialing Addr.
	// If nil, the error is logged and src is closed.
	// If non-nil, src is not closed automatically.
	OnDialError func(src net.Conn, dstDialErr error)
}

// UnderlyingConn returns c.Conn if c of type *Conn,
// otherwise it returns c.
func UnderlyingConn(c net.Conn) net.Conn {
	if wrap, ok := c.(*Conn); ok {
		return wrap.Conn
	}
	return c
}

// HandleConn implements the Target interface.
func (dp *DialProxy) HandleConn(src net.Conn) {
	ctx := context.Background()
	var cancel context.CancelFunc
	if dp.DialTimeout >= 0 {
		ctx, cancel = context.WithTimeout(ctx, dp.dialTimeout())
	}
	dst, err := dp.dialContext()(ctx, "tcp", dp.Addr)
	if cancel != nil {
		cancel()
	}
	if err != nil {
		dp.onDialError()(src, err)
		return
	}
	defer src.Close()
	defer dst.Close()
	if ka := dp.keepAlivePeriod(); ka > 0 {
		if c, ok := UnderlyingConn(src).(*net.TCPConn); ok {
			c.SetKeepAlive(true)
			c.SetKeepAlivePeriod(ka)
		}
		if c, ok := dst.(*net.TCPConn); ok {
			c.SetKeepAlive(true)
			c.SetKeepAlivePeriod(ka)
		}
	}
	errc := make(chan error, 1)
	go proxyCopy(errc, src, dst)
	go proxyCopy(errc, dst, src)
	<-errc
}

// proxyCopy is the function that copies bytes around.
// It's a named function instead of a func literal so users get
// named goroutines in debug goroutine stack dumps.
func proxyCopy(errc chan<- error, dst io.Writer, src io.Reader) {
	// TODO: make caller switch from src to rawSrc after N bytes (e.g. 4KB)
	// if the io.Copy optimization to switch to Linux splice happens.
	// TODO: if the runtime provides a way to wait for
	// readability, use that to avoid stranding big blocks of
	// memory blocked in idle reads.
	_, err := io.Copy(dst, src)
	errc <- err
}

func (dp *DialProxy) keepAlivePeriod() time.Duration {
	if dp.KeepAlivePeriod != 0 {
		return dp.KeepAlivePeriod
	}
	return time.Minute
}

func (dp *DialProxy) dialTimeout() time.Duration {
	if dp.DialTimeout > 0 {
		return dp.DialTimeout
	}
	return 10 * time.Second
}

var defaultDialer = new(net.Dialer)

func (dp *DialProxy) dialContext() func(ctx context.Context, network, address string) (net.Conn, error) {
	if dp.DialContext != nil {
		return dp.DialContext
	}
	return defaultDialer.DialContext
}

func (dp *DialProxy) onDialError() func(src net.Conn, dstDialErr error) {
	if dp.OnDialError != nil {
		return dp.OnDialError
	}
	return func(src net.Conn, dstDialErr error) {
		log.Printf("tcpproxy: for incoming conn %v, error dialing %q: %v", src.RemoteAddr().String(), dp.Addr, dstDialErr)
		src.Close()
	}
}
