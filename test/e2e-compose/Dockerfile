# Test image: packages a binary built on the host (CGO_ENABLED=0 go build -o bin/sherlock ./cmd/sherlock).
FROM gcr.io/distroless/static-debian12:nonroot
COPY bin/sherlock /sherlock
USER 65532:65532
ENTRYPOINT ["/sherlock"]
