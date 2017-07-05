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

package tcpproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
)

func TestMatchHTTPHost(t *testing.T) {
	tests := []struct {
		name string
		r    io.Reader
		host string
		want bool
	}{
		{
			name: "match",
			r:    strings.NewReader("GET / HTTP/1.1\r\nHost: foo.com\r\n\r\n"),
			host: "foo.com",
			want: true,
		},
		{
			name: "no-match",
			r:    strings.NewReader("GET / HTTP/1.1\r\nHost: foo.com\r\n\r\n"),
			host: "bar.com",
			want: false,
		},
		{
			name: "match-huge-request",
			r:    io.MultiReader(strings.NewReader("GET / HTTP/1.1\r\nHost: foo.com\r\n"), neverEnding('a')),
			host: "foo.com",
			want: true,
		},
	}
	for i, tt := range tests {
		name := tt.name
		if name == "" {
			name = fmt.Sprintf("test_index_%d", i)
		}
		t.Run(name, func(t *testing.T) {
			br := bufio.NewReader(tt.r)
			var matcher matcher = httpHostMatch(tt.host)
			got := matcher.match(br)
			if got != tt.want {
				t.Fatalf("match = %v; want %v", got, tt.want)
			}
			get := make([]byte, 3)
			if _, err := io.ReadFull(br, get); err != nil {
				t.Fatal(err)
			}
			if string(get) != "GET" {
				t.Fatalf("did bufio.Reader consume bytes? got %q; want GET", get)
			}
		})
	}
}

type neverEnding byte

func (b neverEnding) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = byte(b)
	}
	return len(p), nil
}

type recordWritesConn struct {
	buf bytes.Buffer
	net.Conn
}

func (c *recordWritesConn) Write(p []byte) (int, error) {
	c.buf.Write(p)
	return len(p), nil
}

func (c *recordWritesConn) Read(p []byte) (int, error) { return 0, io.EOF }

func clientHelloRecord(t *testing.T, hostName string) string {
	rec := new(recordWritesConn)
	cl := tls.Client(rec, &tls.Config{ServerName: hostName})
	cl.Handshake()

	s := rec.buf.String()
	if !strings.Contains(s, hostName) {
		t.Fatalf("clientHello sent in test didn't contain %q", hostName)
	}
	return s
}

func TestSNI(t *testing.T) {
	const hostName = "foo.com"
	greeting := clientHelloRecord(t, hostName)
	got := clientHelloServerName(bufio.NewReader(strings.NewReader(greeting)))
	if got != hostName {
		t.Errorf("got SNI %q; want %q", got, hostName)
	}
}

func TestProxyStartNone(t *testing.T) {
	var p Proxy
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
}

func newLocalListener(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		ln, err = net.Listen("tcp", "[::1]:0")
		if err != nil {
			t.Fatal(err)
		}
	}
	return ln
}

const testFrontAddr = "1.2.3.4:567"

func testListenFunc(t *testing.T, ln net.Listener) func(network, laddr string) (net.Listener, error) {
	return func(network, laddr string) (net.Listener, error) {
		if network != "tcp" {
			t.Errorf("got Listen call with network %q, not tcp", network)
			return nil, errors.New("invalid network")
		}
		if laddr != testFrontAddr {
			t.Fatalf("got Listen call with laddr %q, want %q", laddr, testFrontAddr)
			panic("bogus address")
		}
		return ln, nil
	}
}

func testProxy(t *testing.T, front net.Listener) *Proxy {
	return &Proxy{
		ListenFunc: testListenFunc(t, front),
	}
}

func TestProxyAlwaysMatch(t *testing.T) {
	front := newLocalListener(t)
	defer front.Close()
	back := newLocalListener(t)
	defer back.Close()

	p := testProxy(t, front)
	p.AddRoute(testFrontAddr, To(back.Addr().String()))
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}

	toFront, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer toFront.Close()

	fromProxy, err := back.Accept()
	if err != nil {
		t.Fatal(err)
	}
	const msg = "message"
	io.WriteString(toFront, msg)

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(fromProxy, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Fatalf("got %q; want %q", buf, msg)
	}
}

func TestProxyHTTP(t *testing.T) {
	front := newLocalListener(t)
	defer front.Close()

	backFoo := newLocalListener(t)
	defer backFoo.Close()
	backBar := newLocalListener(t)
	defer backBar.Close()

	p := testProxy(t, front)
	p.AddHTTPHostRoute(testFrontAddr, "foo.com", To(backFoo.Addr().String()))
	p.AddHTTPHostRoute(testFrontAddr, "bar.com", To(backBar.Addr().String()))
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}

	toFront, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer toFront.Close()

	const msg = "GET / HTTP/1.1\r\nHost: bar.com\r\n\r\n"
	io.WriteString(toFront, msg)

	fromProxy, err := backBar.Accept()
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(fromProxy, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Fatalf("got %q; want %q", buf, msg)
	}
}

func TestProxySNI(t *testing.T) {
	front := newLocalListener(t)
	defer front.Close()

	backFoo := newLocalListener(t)
	defer backFoo.Close()
	backBar := newLocalListener(t)
	defer backBar.Close()

	p := testProxy(t, front)
	p.AddSNIRoute(testFrontAddr, "foo.com", To(backFoo.Addr().String()))
	p.AddSNIRoute(testFrontAddr, "bar.com", To(backBar.Addr().String()))
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}

	toFront, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer toFront.Close()

	msg := clientHelloRecord(t, "bar.com")
	io.WriteString(toFront, msg)

	fromProxy, err := backBar.Accept()
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(fromProxy, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Fatalf("got %q; want %q", buf, msg)
	}
}
