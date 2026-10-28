# ADR-0011: CRS ships inside releases

- Status: Accepted
- Date: 2026-10-28

## Context

PCI DSS 6.4.2 requires the WAF to be "up to date". Rules can be updated separately from the binary (as some existing WAF products do) or bundled.

## Decision

The CRS version is embedded in each Sherlock release. When CRS publishes a security fix, Sherlock publishes a patch release within 72 hours (target) that bumps CRS only. The dashboard shows the CRS version and its age, and warns when a newer Sherlock patch with a CRS update exists.

## Consequences

Every rule version is tested by our CI before users get it; simpler mental model ("version X = rules Y"); offline sites update rules the same way they update the binary. The cost is a release per CRS security fix, which the automated pipeline makes cheap. Enterprise may offer a CRS LTS track.
