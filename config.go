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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
)

// A Route maps a match on a domain name to a backend.
type Route struct {
	match     *regexp.Regexp
	backend   string
	proxyInfo bool
}

// Config stores the TLS routing configuration.
type Config struct {
	mu     sync.Mutex
	routes []Route
	acme   *ACME
}

func dnsRegex(s string) (*regexp.Regexp, error) {
	if len(s) >= 2 && s[0] == '/' && s[len(s)-1] == '/' {
		return regexp.Compile(s[1 : len(s)-1])
	}

	var b []string
	for _, f := range strings.Split(s, ".") {
		switch f {
		case "*":
			b = append(b, `[^.]+`)
		case "":
			return nil, fmt.Errorf("DNS name %q has empty label", s)
		default:
			b = append(b, regexp.QuoteMeta(f))
		}
	}
	return regexp.Compile(fmt.Sprintf("^%s$", strings.Join(b, `\.`)))
}

// Match returns the backend for hostname, and whether to use the PROXY protocol.
func (c *Config) Match(hostname string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if strings.HasSuffix(hostname, ".acme.invalid") {
		return c.acme.Match(hostname), false
	}

	for _, r := range c.routes {
		if r.match.MatchString(hostname) {
			return r.backend, r.proxyInfo
		}
	}
	return "", false
}

// Read replaces the current Config with one read from r.
func (c *Config) Read(r io.Reader) error {
	var routes []Route
	var backends []string

	s := bufio.NewScanner(r)
	for s.Scan() {
		if strings.HasPrefix(strings.TrimSpace(s.Text()), "#") {
			// Comment, ignore.
			continue
		}

		fs := strings.Fields(s.Text())
		switch len(fs) {
		case 0:
			continue
		case 1:
			return fmt.Errorf("invalid %q on a line by itself", s.Text())
		case 2:
			re, err := dnsRegex(fs[0])
			if err != nil {
				return err
			}
			routes = append(routes, Route{re, fs[1], false})
			backends = append(backends, fs[1])
		case 3:
			re, err := dnsRegex(fs[0])
			if err != nil {
				return err
			}
			if fs[2] != "PROXY" {
				return errors.New("third item on a line can only be PROXY")
			}
			routes = append(routes, Route{re, fs[1], true})
			backends = append(backends, fs[1])
		default:
			// TODO: multiple backends?
			return fmt.Errorf("too many fields on line: %q", s.Text())
		}
	}
	if err := s.Err(); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.routes = routes
	c.acme = &ACME{
		backends: backends,
		cache:    make(map[string]acmeCacheEntry),
	}
	return nil
}

// ReadFile replaces the current Config with one read from path.
func (c *Config) ReadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return c.Read(f)
}

// ReadString replaces the current Config with one read from cfg.
func (c *Config) ReadString(cfg string) error {
	b := bytes.NewBufferString(cfg)
	return c.Read(b)
}
