package main

import (
	"bytes"
	"testing"
)

func TestConfig(t *testing.T) {
	cases := []struct {
		Config string
		Tests  map[string]string
	}{
		{
			Config: `
# Comment
go.universe.tf 1.2.3.4
*.universe.tf 2.3.4.5
# Comment
google.* 3.4.5.6
/gooo+gle\.com/ 4.5.6.7
`,
			Tests: map[string]string{
				"go.universe.tf":     "1.2.3.4",
				"foo.universe.tf":    "2.3.4.5",
				"bar.universe.tf":    "2.3.4.5",
				"google.com":         "3.4.5.6",
				"google.fr":          "3.4.5.6",
				"goooooooooogle.com": "4.5.6.7",

				"blah.com":            "",
				"google.com.br":       "",
				"foo.bar.universe.tf": "",
				"goooooglexcom":       "",
			},
		},
	}

	for _, test := range cases {
		var cfg Config
		if err := cfg.Read(bytes.NewBufferString(test.Config)); err != nil {
			t.Fatalf("Failed to read config (%s):\n%q", err, test.Config)
		}

		for hostname, expected := range test.Tests {
			actual := cfg.Match(hostname)
			if expected != actual {
				t.Errorf("cfg.Match(%q) is %q, want %q", hostname, actual, expected)
			}
		}
	}
}
