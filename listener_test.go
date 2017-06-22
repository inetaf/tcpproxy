// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tcpproxy

import (
	"io"
	"testing"
)

func TestListenerAccept(t *testing.T) {
	tl := new(TargetListener)
	ch := make(chan interface{}, 1)
	go func() {
		for {
			conn, err := tl.Accept()
			if err != nil {
				ch <- err
				return
			} else {
				ch <- conn
			}
		}
	}()

	for i := 0; i < 3; i++ {
		conn := new(Conn)
		tl.HandleConn(conn)
		got := <-ch
		if got != conn {
			t.Errorf("Accept conn = %v; want %v", got, conn)
		}
	}
	tl.Close()
	got := <-ch
	if got != io.EOF {
		t.Errorf("Accept error post-Close = %v; want io.EOF", got)
	}
}
