# Security Policy

WPTV is a forensic investigation tool used inside Wazuh environments, often against sensitive telemetry (process trees, command lines, credentials-adjacent artifacts). Security issues in this project are taken seriously.

## Supported Versions

WPTV is currently validated against the following Wazuh versions:

| **Wazuh Version** | **OpenSearch Dashboards** | **WPTV Support** |
| ------------------ | ------------------------- | ---------------- |
| 4.14.7             | 2.19.5                    | ✅ Validated |
| 4.14.4             | 2.19.4                    | ✅ Validated |
| 5.x                | —                         | ❌ Not validated |
| < 4.14             | —                         | ❌ Not validated |

> **Compatibility note:** WPTV v2.1 was initially developed and validated with Wazuh 4.14.4, which uses OpenSearch Dashboards 2.19.4. Subsequent testing with Wazuh 4.14.7 identified an OpenSearch Dashboards version change to 2.19.5. The WPTV OSD plugin manifest must match the installed OpenSearch Dashboards version for the plugin to load correctly. See the README for the version-specific deployment requirements.

Only the versions marked "Validated" above receive security fixes. There is no long-term support for unvalidated Wazuh versions.

## Reporting a Vulnerability

We use **GitHub Security Advisories** to manage vulnerability reports. If you find a security vulnerability in WPTV, please:

1. Go to the **"Security"** tab of this repository.
2. Click **"Advisories"** and then **"Report a vulnerability"**.
3. Provide the vulnerability details and steps to reproduce.

This keeps the report private while we investigate and work on a fix.

**Please do not open a public Issue for security vulnerabilities.**

## Scope

This policy covers the WPTV backend (`process_tree_api/`), the OpenSearch Dashboards plugin (`wptv_plugin/`), and the deployment configuration described in `README.md` (Nginx, systemd unit, Indexer service account permissions).

Examples of in-scope issues:

- Authentication or authorization bypass in the WPTV backend or Indexer service account setup
- Injection vulnerabilities (query injection against the Wazuh Indexer, XSS in the frontend, etc.)
- Exposure of `WPTV_INDEXER_PASSWORD`, `WPTV_ANTHROPIC_API_KEY`, or other secrets through logs, error messages, or the frontend
- Server-Side Request Forgery (SSRF) or path traversal in the backend
- Any way for one Wazuh agent's data to leak into another agent's process tree

Out of scope:

- Vulnerabilities in Wazuh itself, OpenSearch Dashboards, or third-party dependencies (report these upstream)
- Vulnerabilities requiring an already-compromised Wazuh Indexer or Wazuh Manager
- The AI Analyzer's data flow to the Anthropic API is a documented, intentional design choice (see `README.md` → AI Analyzer → Data flow disclaimer), not a vulnerability in itself

## Response

This is an independent, community-maintained project developed as part of the Wazuh Ambassador Program - not an officially supported Wazuh product. There is no guaranteed SLA, but reports are reviewed as soon as possible and credited in the release notes unless anonymity is requested.
