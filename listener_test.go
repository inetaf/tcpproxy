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
			}
			ch <- conn
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
