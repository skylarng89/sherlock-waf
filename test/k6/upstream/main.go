// Command upstream is the benchmark origin: it answers every request with a
// fixed 1 KB body as fast as Go allows, so measured latency is Sherlock's and
// not the application's.
package main

import (
	"bytes"
	"flag"
	"log"
	"net/http"
	"strconv"
	"time"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:18101", "listen address")
	flag.Parse()

	body := bytes.Repeat([]byte("sherlock-benchmark-"), 54)[:1024]
	length := strconv.Itoa(len(body))
	srv := &http.Server{
		Addr:              *addr,
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Length", length)
			_, _ = w.Write(body)
		}),
	}
	log.Fatal(srv.ListenAndServe())
}
