# Security policy

## Reporting a vulnerability

Please do not disclose suspected vulnerabilities publicly or test against other users. Send a report to **{{SECURITY_CONTACT_EMAIL}}** with a description, affected URL or file, reproduction steps, and impact. Do not include real user passwords, session cookies, or other personal information.

This contact is a placeholder and must be replaced with a monitored address before public deployment. The project currently has no formal bug-bounty program or response-time commitment.

## Scope and safe testing

Only test systems you own or have explicit authorization to test. Do not access, modify, or delete another person’s data, perform denial-of-service testing, or use social engineering. Give the operator a reasonable opportunity to investigate and fix a report before public disclosure.

## Deployment

Keep `.env`, session secrets, SMTP credentials, SQLite databases, and backups out of source control. Run behind HTTPS in production, use supported dependency versions, and maintain private backups and a tested restoration process.
