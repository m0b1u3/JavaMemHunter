# Contributing to JavaMemHunter

Thanks for your interest! JavaMemHunter is open-sourced for the security
community under Apache License 2.0. It reached **v1.0** (production-ready
detect / score / clean / verify for Behinder agent, Godzilla filter, and
JSP webshells). Contributions adding new shell types or container support
are very welcome.

## Prerequisites

- JDK 17 (build + integration tests run on 17)
- JDK 8 optional (only needed if you reproduce the Windows + JDK 17 NIO
  selector workaround locally)
- Maven Wrapper (`./mvnw` / `mvnw.cmd`) — do not require a system `mvn`

## Build and test

```bash
./mvnw -DskipITs verify                              # unit tests
./mvnw -pl integration-tests -Psb27 verify           # Spring Boot 2.7 E2E
./mvnw -pl integration-tests -Psb32 verify           # Spring Boot 3.2 E2E
```

## Submitting changes

1. Open an issue first for any non-trivial change, so we can agree on the
   approach before you spend time on a PR.
2. Branch from `master`: `feature/<short-name>`.
3. Write tests first (TDD). New cleaners or scanners must have unit tests
   covering happy path + at least one failure mode.
4. Run `./mvnw verify` locally before pushing.
5. Open a PR using the template; CI must pass.

## Coding style

- Follow the existing indentation and naming. No formatter is enforced;
  match the surrounding code.
- Keep files focused. If a class grows past ~400 lines or accrues
  unrelated responsibilities, propose a split.
- Reflection-heavy code lives in `agent/.../compat/` and
  `agent/.../cleaner/`. New servlet-API references must go through
  `ServletApiBridge` so they stay javax/jakarta neutral.

## Issue triage labels

- `bug` — reproducible defect
- `enhancement` — new capability
- `good first issue` — small, well-scoped, documented
- `help wanted` — accepted but maintainers can't immediately work on it
- `wontfix` — out of scope or rejected

## DCO / signoff

Not required at this stage.

## Security disclosure

If you find a vulnerability, **do not file a public issue**. Report it
privately via GitHub Security Advisories: go to the repository's
**Security** tab → **Report a vulnerability**. We'll respond and
coordinate a fix and disclosure.
