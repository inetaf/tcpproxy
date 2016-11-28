package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
)

type Route struct {
	match   *regexp.Regexp
	backend string
}

// Config stores the TLS routing configuration.
type Config struct {
	mu     sync.Mutex
	routes []Route
}

func dnsRegex(s string) (*regexp.Regexp, error) {
	return regexp.Compile(s)
}

func (c *Config) Match(hostname string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.routes {
		if r.match.MatchString(hostname) {
			return r.backend
		}
	}
	return ""
}

func (c *Config) Read(r io.Reader) error {
	var routes []Route

	s := bufio.NewScanner(r)
	for s.Scan() {
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
			routes = append(routes, Route{re, fs[1]})
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
	return nil
}

func (c *Config) ReadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return c.Read(f)
}
