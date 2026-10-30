// Command backend is the upstream for the go-ftw CRS regression run: it
// accepts every method and URI with 200 and a fixed body, which is all the CRS
// tests need from an application.
package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"time"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:18081", "listen address")
	flag.Parse()

	srv := &http.Server{
		Addr:              *addr,
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "ok\n")
		}),
	}
	log.Fatal(srv.ListenAndServe())
}
