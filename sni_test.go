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
	"testing"
)

func slice(l int) []byte {
	ret := make([]byte, l)
	for i := 0; i < l; i++ {
		ret[i] = byte(i)
	}
	return ret
}

func vec(l, lenBytes int) []byte {
	b := slice(l)
	vecLen := len(b)
	ret := make([]byte, vecLen+l)
	for i := l - 1; i >= 0; i-- {
		ret[i] = byte(vecLen & 0xff)
		vecLen >>= 8
	}
	copy(ret[l:], b)
	return ret
}

func packet(bs ...[]byte) []byte {
	var ret []byte
	for _, b := range bs {
		ret = append(ret, b...)
	}
	return ret
}

func offset(b []byte, off int) []byte {
	return b[off:]
}

func TestVector(t *testing.T) {
	tests := []struct {
		in         []byte
		inLen      int
		out1, out2 []byte
		err        bool
	}{
		{
			// 1b length
			append([]byte{3}, slice(10)...), 1,
			slice(3), offset(slice(10), 3), false,
		},
		{
			// 1b length, no trailer
			append([]byte{10}, slice(10)...), 1,
			slice(10), []byte{}, false,
		},
		{
			// 1b length, no vector
			append([]byte{0}, slice(10)...), 1,
			[]byte{}, slice(10), false,
		},
		{
			// 1b length, no vector or trailer
			[]byte{0}, 1,
			[]byte{}, []byte{}, false,
		},
		{
			// 2b length, LSB only
			append([]byte{0, 3}, slice(10)...), 2,
			slice(3), offset(slice(10), 3), false,
		},
		{
			// 2b length, MSB only
			append([]byte{3, 0}, slice(1024)...), 2,
			slice(768), offset(slice(1024), 768), false,
		},
		{
			// 2b length, both bytes
			append([]byte{3, 2}, slice(1024)...), 2,
			slice(770), offset(slice(1024), 770), false,
		},
		{
			// 3b length
			append([]byte{1, 2, 3}, slice(100000)...), 3,
			slice(66051), offset(slice(100000), 66051), false,
		},
		{
			// no bytes
			[]byte{}, 1,
			nil, nil, true,
		},
		{
			// no slice
			nil, 1,
			nil, nil, true,
		},
		{
			// not enough bytes for length
			[]byte{1}, 2,
			nil, nil, true,
		},
		{
			// no bytes after length
			[]byte{1}, 1,
			nil, nil, true,
		},
		{
			// not enough bytes for vector
			[]byte{4, 1, 2}, 1,
			nil, nil, true,
		},
	}

	for _, test := range tests {
		actual1, actual2, err := vector(test.in, test.inLen)
		if !test.err && (err != nil) {
			t.Errorf("unexpected error %q", err)
		}
		if test.err && (err == nil) {
			t.Errorf("unexpected success")
		}
		if err != nil {
			continue
		}
		if !bytes.Equal(actual1, test.out1) {
			t.Errorf("wrong bytes for vector slice. Got %#v, want %#v", actual1, test.out1)
		}
		if !bytes.Equal(actual2, test.out2) {
			t.Errorf("wrong bytes for vector slice. Got %#v, want %#v", actual2, test.out2)
		}
	}
}

func TestHandshakeRecord(t *testing.T) {
	tests := []struct {
		in     []byte
		out    []byte
		tlsver int
	}{
		{
			// TLS 1.0, 1b packet
			[]byte{22, 3, 1, 0, 1, 3},
			[]byte{3},
			1,
		},
		{
			// TLS 1.1, 1b packet
			[]byte{22, 3, 2, 0, 1, 3},
			[]byte{3},
			2,
		},
		{
			// TLS 1.2, 1b packet
			[]byte{22, 3, 3, 0, 1, 3},
			[]byte{3},
			3,
		},
		{
			// TLS 1.2, no payload bytes
			[]byte{22, 3, 3, 0, 0},
			[]byte{},
			3,
		},
		{
			// TLS 1.2, >255b payload w/ trailing stuff
			append([]byte{22, 3, 3, 3, 2}, slice(1024)...),
			slice(770),
			3,
		},
		{
			// TLS 1.2, 2^14 payload
			append([]byte{22, 3, 3, 64, 0}, slice(maxTLSRecordLength)...),
			slice(maxTLSRecordLength),
			3,
		},
		{
			// TLS 1.2, >2^14 payload
			append([]byte{22, 3, 3, 64, 1}, slice(maxTLSRecordLength+1)...),
			nil,
			0,
		},
		{
			// TLS 1.2, truncated payload
			[]byte{22, 3, 3, 0, 4, 1, 2},
			nil,
			0,
		},
		{
			// truncated header
			[]byte{22},
			nil,
			0,
		},
		{
			// wrong record type
			[]byte{42, 3, 3, 0, 1, 3},
			nil,
			0,
		},
		{
			// wrong TLS major version
			[]byte{22, 2, 3, 0, 1, 3},
			nil,
			0,
		},
		{
			// wrong TLS minor version
			[]byte{22, 3, 42, 0, 1, 3},
			nil,
			0,
		},
		{
			// Obsolete SSL 3.0
			[]byte{22, 3, 0, 0, 1, 3},
			nil,
			0,
		},
	}

	for _, test := range tests {
		r := bytes.NewBuffer(test.in)
		actual, tlsver, err := handshakeRecord(r)
		if test.out == nil && err == nil {
			t.Errorf("unexpected success")
			continue
		}
		if !bytes.Equal(test.out, actual) {
			t.Errorf("wrong bytes for TLS record. Got %#v, want %#v", actual, test.out)
		}
		if tlsver != test.tlsver {
			t.Errorf("wrong TLS version returned. Got %d, want %d", tlsver, test.tlsver)
		}
	}
}

func TestParseHello(t *testing.T) {
	tests := []struct {
		in  []byte
		out []byte
		err bool
	}{
		{
			// Wrong record type
			packet([]byte{42, 0, 0, 1, 1}),
			nil,
			true,
		},
		{
			// Truncated payload
			packet([]byte{1, 0, 0, 1}),
			nil,
			true,
		},
		{
			// Payload too small
			packet([]byte{1, 0, 0, 1, 1}),
			nil,
			true,
		},
		{
			// Unknown major version
			packet([]byte{1, 0, 0, 34, 1, 0}, slice(32)),
			nil,
			true,
		},
		{
			// Unknown minor version
			packet([]byte{1, 0, 0, 34, 3, 42}, slice(32)),
			nil,
			true,
		},
		{
			// Missing required variadic fields
			packet([]byte{1, 0, 0, 34, 3, 1}, slice(32)),
			nil,
			true,
		},
		{
			// All zero variadic fields (no ciphersuites, no compression)
			packet([]byte{1, 0, 0, 38, 3, 1}, slice(32), []byte{0, 0, 0, 0}),
			nil,
			true,
		},
		{
			// All zero variadic fields (no ciphersuites, no compression, nonzero session ID)
			packet([]byte{1, 0, 0, 70, 3, 1}, slice(32), []byte{32}, slice(32), []byte{0, 0, 0}),
			nil,
			true,
		},
		{
			// Session + ciphersuites, no compression
			packet([]byte{1, 0, 0, 72, 3, 1}, slice(32), []byte{32}, slice(32), []byte{0, 2, 1, 2, 0}),
			nil,
			true,
		},
		{
			// First valid packet. TLS 1.0, no extensions present.
			packet([]byte{1, 0, 0, 73, 3, 1}, slice(32), []byte{32}, slice(32), []byte{0, 2, 1, 2, 1, 0}),
			nil,
			false,
		},
		{
			// TLS 1.1, no extensions present.
			packet([]byte{1, 0, 0, 73, 3, 2}, slice(32), []byte{32}, slice(32), []byte{0, 2, 1, 2, 1, 0}),
			nil,
			false,
		},
		{
			// TLS 1.2, no extensions present.
			packet([]byte{1, 0, 0, 73, 3, 3}, slice(32), []byte{32}, slice(32), []byte{0, 2, 1, 2, 1, 0}),
			nil,
			false,
		},
		{
			// TLS 1.2, garbage extensions
			packet([]byte{1, 0, 0, 115, 3, 3}, slice(32), []byte{32}, slice(32), []byte{0, 2, 1, 2, 1, 0}, slice(42)),
			nil,
			true,
		},
		{
			// empty extensions vector
			packet([]byte{1, 0, 0, 75, 3, 3}, slice(32), []byte{32}, slice(32), []byte{0, 2, 1, 2, 1, 0}, []byte{0, 0}),
			nil,
			false,
		},
		{
			// non-SNI extensions
			packet([]byte{1, 0, 0, 85, 3, 3}, slice(32), []byte{32}, slice(32), []byte{0, 2, 1, 2, 1, 0}, []byte{0, 10, 42, 42, 0, 0, 100, 100, 0, 2, 1, 2}),
			nil,
			false,
		},
		{
			// SNI present
			packet([]byte{1, 0, 0, 90, 3, 3}, slice(32), []byte{32}, slice(32), []byte{0, 2, 1, 2, 1, 0}, []byte{0, 15, 42, 42, 0, 0, 100, 100, 0, 2, 1, 2, 0, 0, 0, 1, 182}),
			[]byte{182},
			false,
		},
		{
			// Longer SNI
			packet([]byte{1, 0, 0, 93, 3, 3}, slice(32), []byte{32}, slice(32), []byte{0, 2, 1, 2, 1, 0}, []byte{0, 18, 42, 42, 0, 0, 100, 100, 0, 2, 1, 2, 0, 0, 0, 4}, slice(4)),
			slice(4),
			false,
		},
		{
			// Embedded SNI
			packet([]byte{1, 0, 0, 93, 3, 3}, slice(32), []byte{32}, slice(32), []byte{0, 2, 1, 2, 1, 0}, []byte{0, 18, 42, 42, 0, 0, 0, 0, 0, 4}, slice(4), []byte{100, 100, 0, 2, 1, 2}),
			slice(4),
			false,
		},
	}

	for _, test := range tests {
		actual, err := parseHello(test.in)
		if test.err {
			if err == nil {
				t.Errorf("unexpected success")
			}
			continue
		}
		if err != nil {
			t.Errorf("unexpected error %q", err)
			continue
		}
		if !bytes.Equal(test.out, actual) {
			t.Errorf("wrong bytes for SNI data. Got %#v, want %#v", actual, test.out)
		}
	}
}

func TestParseSNI(t *testing.T) {
	tests := []struct {
		in  []byte
		out string
		err bool
	}{
		{
			// Empty packet
			[]byte{},
			"",
			true,
		},
		{
			// Truncated packet
			[]byte{0, 2, 1},
			"",
			true,
		},
		{
			// Truncated packet within SNI vector
			[]byte{0, 2, 1, 2},
			"",
			true,
		},
		{
			// Wrong SNI kind
			[]byte{0, 3, 1, 0, 0},
			"",
			false,
		},
		{
			// Right SNI kind, no hostname
			[]byte{0, 3, 0, 0, 0},
			"",
			false,
		},
		{
			// SNI hostname
			packet([]byte{0, 6, 0, 0, 3}, []byte("lol")),
			"lol",
			false,
		},
		{
			// Multiple SNI kinds
			packet([]byte{0, 13, 1, 0, 0, 0, 0, 3}, []byte("lol"), []byte{42, 0, 1, 2}),
			"lol",
			false,
		},
		{
			// Multiple SNI hostnames (illegal, but we just return the first)
			packet([]byte{0, 13, 1, 0, 0, 0, 0, 3}, []byte("bar"), []byte{0, 0, 3}, []byte("lol")),
			"bar",
			false,
		},
	}

	for _, test := range tests {
		actual, err := parseSNI(test.in)
		if test.err {
			if err == nil {
				t.Errorf("unexpected success")
			}
			continue
		}
		if err != nil {
			t.Errorf("unexpected error %q", err)
			continue
		}
		if test.out != actual {
			t.Errorf("wrong SNI hostname. Got %q, want %q", actual, test.out)
		}
	}
}
