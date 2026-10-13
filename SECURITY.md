# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.2.x   | Yes       |
| 0.1.x   | No        |

## Reporting a vulnerability

Please do **not** open a public issue. Report privately through GitHub
Security Advisories: open the repository's **Security** tab and click
**Report a vulnerability**
(<https://github.com/A-Line-Services/session-guard/security/advisories/new>).

Include the affected version, feature flags, a minimal reproduction and the
impact you expect.

## Scope

In scope:

- Token handling: generation, hashing, comparison, storage and leakage.
- Rotation and reuse detection: races, replays or bypasses that let a stolen
  token stay valid.
- Risk-check bypasses: evading scoring, step-up or revocation decisions.
- Cookie handling: attribute defaults, parsing and injection.
- Header parsing panics or DoS (cookies, `X-Forwarded-For`, `User-Agent`).

Out of scope: vulnerabilities in your application's own authentication flow,
or misconfiguration that the documentation already warns against (for
example trusting forwarded headers from untrusted proxies).

## Response

- Acknowledgement within 3 business days.
- Initial assessment within 7 days.
- A fix and coordinated disclosure (advisory, RustSec entry and patched
  release) as soon as practical, usually within 30 days. Reporters are
  credited unless they prefer otherwise.
