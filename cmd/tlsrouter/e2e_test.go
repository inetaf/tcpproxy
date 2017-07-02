package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	proxyproto "github.com/armon/go-proxyproto"
)

func TestRouting(t *testing.T) {
	// Backend servers
	s1, err := serveTLS(t, "server1", false, "test.com")
	if err != nil {
		t.Fatalf("serve TLS server1: %s", err)
	}
	defer s1.Close()

	s2, err := serveTLS(t, "server2", false, "foo.net")
	if err != nil {
		t.Fatalf("serve TLS server2: %s", err)
	}
	defer s2.Close()

	s3, err := serveTLS(t, "server3", false, "blarghblargh.acme.invalid")
	if err != nil {
		t.Fatalf("server TLS server3: %s", err)
	}
	defer s3.Close()

	s4, err := serveTLS(t, "server4", true, "proxy.design")
	if err != nil {
		t.Fatalf("server TLS server4: %s", err)
	}
	defer s4.Close()

	// One proxy
	var p Proxy
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("create listener: %s", err)
	}
	defer l.Close()
	go p.Serve(l)

	if err := p.Config.ReadString(fmt.Sprintf(`
test.com %s
foo.net %s
borkbork.tf %s
proxy.design %s PROXY
`, s1.Addr(), s2.Addr(), s3.Addr(), s4.Addr())); err != nil {
		t.Fatalf("configure proxy: %s", err)
	}

	for _, test := range []struct {
		N, V        string
		P           *x509.CertPool
		OK          bool
		Transparent bool
	}{
		{"test.com", "server1", s1.Pool, true, false},
		{"foo.net", "server2", s2.Pool, true, false},
		{"bar.org", "", s1.Pool, false, false},
		{"blarghblargh.acme.invalid", "server3", s3.Pool, true, false},
		{"proxy.design", "server4", s4.Pool, true, true},
	} {
		res, transparent, err := getTLS(l.Addr().String(), test.N, test.P)
		switch {
		case test.OK && err != nil:
			t.Fatalf("get %q failed: %s", test.N, err)
		case !test.OK && err == nil:
			t.Fatalf("get %q should have failed, but returned %q", test.N, res)
		case test.OK && res != test.V:
			t.Fatalf("got wrong value from %q, got %q, want %q", test.N, res, test.V)
		case test.OK && transparent != test.Transparent:
			t.Fatalf("connection transparency for %q was %v, want %v", test.N, transparent, test.Transparent)
		}
	}
}

// getTLS attempts to set up a TLS session using the given proxy
// address, domain, and cert pool. It returns the value served by the
// server, as well as a bool indicating whether the server knew the
// true client address, indicating that the PROXY protocol was in use.
func getTLS(addr string, domain string, pool *x509.CertPool) (string, bool, error) {
	cfg := tls.Config{
		RootCAs:    pool,
		ServerName: domain,
	}
	conn, err := tls.Dial("tcp", addr, &cfg)
	if err != nil {
		return "", false, fmt.Errorf("dial TLS %q for %q: %s", addr, domain, err)
	}
	defer conn.Close()
	bs, err := ioutil.ReadAll(conn)
	if err != nil {
		return "", false, fmt.Errorf("read TLS from %q (domain %q): %s", addr, domain, err)
	}
	fs := strings.Split(string(bs), " ")
	if len(fs) != 2 {
		return "", false, fmt.Errorf("read TLS from %q (domain %q): incoherent response %q", addr, domain, string(bs))
	}
	transparent := fs[1] == conn.LocalAddr().String()
	return fs[0], transparent, nil
}

type tlsServer struct {
	Domains []string
	Value   string
	Pool    *x509.CertPool
	Test    *testing.T
	NumHits uint32
	l       net.Listener
}

func (s *tlsServer) Serve() {
	for {
		c, err := s.l.Accept()
		if err != nil {
			s.Test.Logf("accept failed on %q: %s", s.Domains, err)
			return
		}
		atomic.AddUint32(&s.NumHits, 1)
		fmt.Fprintf(c, "%s %s", s.Value, c.RemoteAddr())
		c.Close()
	}
}

func (s *tlsServer) Addr() string {
	return s.l.Addr().String()
}

func (s *tlsServer) Close() error {
	return s.l.Close()
}

func serveTLS(t *testing.T, value string, understandProxy bool, domains ...string) (*tlsServer, error) {
	cert, pool, err := selfSignedCert(domains)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	cfg.BuildNameToCertificate()

	var l net.Listener

	l, err = net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, err
	}

	if understandProxy {
		l = &proxyproto.Listener{Listener: l}
	}

	l = tls.NewListener(l, cfg)

	ret := &tlsServer{
		Domains: domains,
		Value:   value,
		Pool:    pool,
		Test:    t,
		l:       l,
	}
	go ret.Serve()
	return ret, nil
}

func selfSignedCert(domains []string) (tls.Certificate, *x509.CertPool, error) {
	pkey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Co"},
			CommonName:   domains[0],
		},
		NotBefore:             time.Time{},
		NotAfter:              time.Now().Add(60 * time.Minute),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              domains[1:],
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &pkey.PublicKey, pkey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	var cert, key bytes.Buffer
	pem.Encode(&cert, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pem.Encode(&key, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pkey)})

	tlscert, err := tls.X509KeyPair(cert.Bytes(), key.Bytes())
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cert.Bytes()) {
		return tls.Certificate{}, nil, fmt.Errorf("failed to add cert %q to pool", domains)
	}

	return tlscert, pool, nil
}
