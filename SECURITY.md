# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately, through GitHub's private vulnerability reporting: open the
repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue or
pull request for a vulnerability.

Include what you found, how to reproduce it, the commit you tested, and the impact you expect. The
report and its follow-up stay in the private advisory until a fix is published.

## Supported versions

Only the latest commit on `main` is supported. There are no release branches.

## Scope

In scope: the control plane (`cmd/`, `internal/`, `migrations/`), the images (`Dockerfile`,
`cmd/echo-runner/Dockerfile`, `cloudbuild.yaml`) and the reference deployment (`infra/`).

A deployment's security also depends on choices its operator makes: who is in the identity map
(`internal/callback_api/transitions_identity_map.json`), which repositories the GitHub App is
installed on, and who holds roles in the Google Cloud project. A weakness that exists only because
of such a choice is a configuration issue rather than a vulnerability in Mercurio, but reports
that show a default or a document leading operators into it are welcome.
