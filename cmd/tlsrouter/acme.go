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
	"context"
	"crypto/tls"
	"net"
	"time"
)

type acmeCacheEntry struct {
	backend string
	expires time.Time
}

// ACME locates backends that are attempting ACME SNI-based validation.
type ACME struct {
	backends []string
	// *.acme.invalid domain to cache entry
	cache map[string]acmeCacheEntry
}

// Match returns the backend for hostname, if one is found.
func (s *ACME) Match(hostname string) string {
	c := s.cache[hostname]
	if time.Now().Before(c.expires) {
		return c.backend
	}

	// Cache entry is either expired or invalid, need to figure out
	// which backend is the right one.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ch := make(chan string, len(s.backends))
	for _, backend := range s.backends {
		go tryAcme(ctx, ch, backend, hostname)
	}
	for range s.backends {
		backend := <-ch
		if backend != "" {
			s.cache[hostname] = acmeCacheEntry{backend, time.Now().Add(5 * time.Second)}
			return backend
		}
	}

	// No usable backends found :(
	s.cache[hostname] = acmeCacheEntry{"", time.Now().Add(5 * time.Second)}
	return ""
}

func tryAcme(ctx context.Context, ch chan string, backend, hostname string) {
	var res string
	var err error
	defer func() { ch <- res }()

	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", backend)
	if err != nil {
		return
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	}
	client := tls.Client(conn, &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	if err = client.Handshake(); err != nil {
		return
	}

	certs := client.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return
	}
	if err = certs[0].VerifyHostname(hostname); err != nil {
		return
	}

	res = backend
}
