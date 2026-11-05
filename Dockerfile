# Release image. GoReleaser builds the binary and passes it in the build
# context; for a local image run `make image`.
# Base pinned by digest (static-debian12:nonroot, multi-arch index).
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/sherlock /usr/local/bin/sherlock

# Runs as the distroless "nonroot" user (65532). Binding ports 80/443 as a
# non-root user needs `--sysctl net.ipv4.ip_unprivileged_port_start=0`
# (Docker) or NET_BIND_SERVICE in the pod's securityContext (Kubernetes).
USER 65532:65532
EXPOSE 80 443
ENTRYPOINT ["/usr/local/bin/sherlock"]
CMD ["run", "--config", "/etc/sherlock/sherlock.yaml", "--data-dir", "/var/lib/sherlock"]
