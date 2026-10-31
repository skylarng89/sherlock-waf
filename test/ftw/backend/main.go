// Command backend is the upstream for the go-ftw CRS regression run. Most
// paths answer 200 with a fixed body, which is all the request-phase tests
// need. /reflect answers with the content the response-phase tests (950-956,
// 959100) put into the request: their payload is {"body": "..."}, and the
// rules under test match the decoded text, so the decoded value is returned
// with the request's Content-Type.
package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"time"
)

// reflectLimit caps what /reflect reads so a stray large request cannot grow
// the response (and the test log) without bound.
const reflectLimit = 1 << 20

type reflectRequest struct {
	Body *string `json:"body"`
}

func main() {
	addr := flag.String("listen", "127.0.0.1:18081", "listen address")
	flag.Parse()

	srv := &http.Server{
		Addr:              *addr,
		ReadHeaderTimeout: 5 * time.Second,
		Handler:           http.HandlerFunc(serve),
	}
	log.Fatal(srv.ListenAndServe())
}

func serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/reflect" {
		reflect(w, r)
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, reflectLimit))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "ok\n")
}

func reflect(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, reflectLimit))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	payload := raw
	var req reflectRequest
	if json.Unmarshal(raw, &req) == nil && req.Body != nil {
		payload = []byte(*req.Body)
	}
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(payload)
}
