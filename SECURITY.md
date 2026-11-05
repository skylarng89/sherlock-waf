# Security policy

Sherlock is security software. We take reports seriously and respond quickly.

## Reporting a vulnerability

- **Do not open a public issue.**
- Use GitHub's private vulnerability reporting ("Report a vulnerability" on the Security tab), or email security@sherlockwaf.com.
- Include affected version, configuration, reproduction steps and impact. WAF bypasses are in scope.

## What to expect

| Step | Target |
| --- | --- |
| Acknowledgement | 3 business days |
| Triage and severity (CVSS 4.0) | 7 days |
| Fix released | Critical 7 days, high 30 days, medium next minor |
| Advisory and CVE | At release; Enterprise customers may be notified up to 72 h earlier |

We credit reporters who wish to be credited. We do not pursue legal action against good-faith research that respects users' privacy and avoids service disruption.

## Supported versions

See `docs/release/support-policy.md`.

## Verifying releases

All release artefacts and images are signed with cosign (keyless, GitHub OIDC). See `docs/release/release-process.md`.
