// Command upstream is the benchmark origin: it answers every request with a
// fixed 1 KB body as fast as Go allows, so measured latency is Sherlock's and
// not the application's. POST /payments (the API benchmark) answers 201 instead,
// and POST /api/login (the login-protection run) answers 200 for the password
// "correct horse" and 401 for anything else.
package main

import (
	"bytes"
	"flag"
	"io"
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
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/payments" {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, `{"status":"created"}`)
				return
			}
			if r.Method == http.MethodPost && r.URL.Path == "/api/login" {
				r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
				_ = r.ParseForm()
				if r.PostForm.Get("password") == "correct horse" {
					_, _ = io.WriteString(w, "welcome")
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Length", length)
			_, _ = w.Write(body)
		}),
	}
	log.Fatal(srv.ListenAndServe())
}
