package main

import (
	"bytes"
	"testing"
)

func TestConfig(t *testing.T) {
	type result struct {
		backend string
		proxy   bool
	}

	cases := []struct {
		Config string
		Tests  map[string]result
	}{
		{
			Config: `
# Comment
go.universe.tf 1.2.3.4
*.universe.tf 2.3.4.5
# Comment
google.* 3.4.5.6
/gooo+gle\.com/ 4.5.6.7
foobar.net 6.7.8.9 PROXY
`,
			Tests: map[string]result{
				"go.universe.tf":     result{"1.2.3.4", false},
				"foo.universe.tf":    result{"2.3.4.5", false},
				"bar.universe.tf":    result{"2.3.4.5", false},
				"google.com":         result{"3.4.5.6", false},
				"google.fr":          result{"3.4.5.6", false},
				"goooooooooogle.com": result{"4.5.6.7", false},
				"foobar.net":         result{"6.7.8.9", true},

				"blah.com":            result{"", false},
				"google.com.br":       result{"", false},
				"foo.bar.universe.tf": result{"", false},
				"goooooglexcom":       result{"", false},
			},
		},
	}

	for _, test := range cases {
		var cfg Config
		if err := cfg.Read(bytes.NewBufferString(test.Config)); err != nil {
			t.Fatalf("Failed to read config (%s):\n%q", err, test.Config)
		}

		for hostname, expected := range test.Tests {
			backend, proxy := cfg.Match(hostname)
			if expected.backend != backend {
				t.Errorf("cfg.Match(%q) is %q, want %q", hostname, backend, expected.backend)
			}
			if expected.proxy != proxy {
				t.Errorf("cfg.Match(%q).proxy is %v, want %v", hostname, proxy, expected.proxy)
			}
		}
	}
}
