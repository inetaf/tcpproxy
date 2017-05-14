// Copyright 2016 Google Inc.
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

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

var (
	cfgFile      = flag.String("conf", "", "configuration file")
	listen       = flag.String("listen", ":443", "listening port")
	helloTimeout = flag.Duration("hello-timeout", 3*time.Second, "how long to wait for the TLS ClientHello")
)

func main() {
	flag.Parse()

	p := &Proxy{}
	if err := p.Config.ReadFile(*cfgFile); err != nil {
		log.Fatalf("Failed to read config %q: %s", *cfgFile, err)
	}

	log.Fatalf("%s", p.ListenAndServe(*listen))
}

// Proxy routes connections to backends based on a Config.
type Proxy struct {
	Config Config
	l      net.Listener
}

// Serve accepts connections from l and routes them according to TLS SNI.
func (p *Proxy) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return fmt.Errorf("accept new conn: %s", err)
		}

		conn := &Conn{
			TCPConn: c.(*net.TCPConn),
			config:  &p.Config,
		}
		go conn.proxy()
	}
}

// ListenAndServe creates a listener on addr calls Serve on it.
func (p *Proxy) ListenAndServe(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("create listener: %s", err)
	}
	return p.Serve(l)
}

// A Conn handles the TLS proxying of one user connection.
type Conn struct {
	*net.TCPConn
	config *Config

	tlsMinor    int
	hostname    string
	backend     string
	backendConn *net.TCPConn
}

func (c *Conn) logf(msg string, args ...interface{}) {
	msg = fmt.Sprintf(msg, args...)
	log.Printf("%s <> %s: %s", c.RemoteAddr(), c.LocalAddr(), msg)
}

func (c *Conn) abort(alert byte, msg string, args ...interface{}) {
	c.logf(msg, args...)
	alertMsg := []byte{21, 3, byte(c.tlsMinor), 0, 2, 2, alert}

	if err := c.SetWriteDeadline(time.Now().Add(*helloTimeout)); err != nil {
		c.logf("error while setting write deadline during abort: %s", err)
		// Do NOT send the alert if we can't set a write deadline,
		// that could result in leaking a connection for an extended
		// period.
		return
	}

	if _, err := c.Write(alertMsg); err != nil {
		c.logf("error while sending alert: %s", err)
	}
}

func (c *Conn) internalError(msg string, args ...interface{}) { c.abort(80, msg, args...) }
func (c *Conn) sniFailed(msg string, args ...interface{})     { c.abort(112, msg, args...) }

func (c *Conn) proxy() {
	defer c.Close()

	if err := c.SetReadDeadline(time.Now().Add(*helloTimeout)); err != nil {
		c.internalError("Setting read deadline for ClientHello: %s", err)
		return
	}

	var (
		err          error
		handshakeBuf bytes.Buffer
	)
	c.hostname, c.tlsMinor, err = extractSNI(io.TeeReader(c, &handshakeBuf))
	if err != nil {
		c.internalError("Extracting SNI: %s", err)
		return
	}

	c.logf("extracted SNI %s", c.hostname)

	if err = c.SetReadDeadline(time.Time{}); err != nil {
		c.internalError("Clearing read deadline for ClientHello: %s", err)
		return
	}

	addProxyHeader := false
	c.backend, addProxyHeader = c.config.Match(c.hostname)
	if c.backend == "" {
		c.sniFailed("no backend found for %q", c.hostname)
		return
	}

	c.logf("routing %q to %q", c.hostname, c.backend)
	backend, err := net.DialTimeout("tcp", c.backend, 10*time.Second)
	if err != nil {
		c.internalError("failed to dial backend %q for %q: %s", c.backend, c.hostname, err)
		return
	}
	defer backend.Close()

	c.backendConn = backend.(*net.TCPConn)

	// If the backend supports the HAProxy PROXY protocol, give it the
	// real source information about the connection.
	if addProxyHeader {
		remote := c.TCPConn.RemoteAddr().(*net.TCPAddr)
		local := c.TCPConn.LocalAddr().(*net.TCPAddr)
		family := "TCP6"
		if remote.IP.To4() != nil {
			family = "TCP4"
		}
		if _, err := fmt.Fprintf(c.backendConn, "PROXY %s %s %s %d %d\r\n", family, remote.IP, local.IP, remote.Port, local.Port); err != nil {
			c.internalError("failed to send PROXY header to %q: %s", c.backend, err)
			return
		}
	}

	// Replay the piece of the handshake we had to read to do the
	// routing, then blindly proxy any other bytes.
	if _, err = io.Copy(c.backendConn, &handshakeBuf); err != nil {
		c.internalError("failed to replay handshake to %q: %s", c.backend, err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go proxy(&wg, c.TCPConn, c.backendConn)
	go proxy(&wg, c.backendConn, c.TCPConn)
	wg.Wait()
}

func proxy(wg *sync.WaitGroup, a, b net.Conn) {
	defer wg.Done()
	atcp, btcp := a.(*net.TCPConn), b.(*net.TCPConn)
	if _, err := io.Copy(atcp, btcp); err != nil {
		log.Printf("%s<>%s -> %s<>%s: %s", atcp.RemoteAddr(), atcp.LocalAddr(), btcp.LocalAddr(), btcp.RemoteAddr(), err)
	}
	btcp.CloseWrite()
	atcp.CloseRead()
}
