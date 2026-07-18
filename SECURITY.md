# Security policy

## Supported version

Security fixes are applied to the current `main` branch. The project does not currently maintain separate supported release branches.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability involving secret handling, tag verification, or a practical forgery.

Use GitHub's private vulnerability reporting for this repository when available:

1. Open the repository's **Security** tab.
2. Select **Advisories**.
3. Select **Report a vulnerability**.

Include the affected commit, reproduction steps using synthetic data, expected and actual behavior, and an assessment of impact. Do not include real GPG secret material, derived HMAC keys, production aliases, mailbox content, or credentials.

If private vulnerability reporting is unavailable, open a public issue containing no sensitive details and ask the maintainer for a private contact channel.

## Scope reminder

MailACL authenticates a truncated alias tag. It does not authenticate message senders, sign message content, configure a mail server, or prevent mailbox compromise and phishing by itself. Reports based only on those documented limitations are not vulnerabilities.
