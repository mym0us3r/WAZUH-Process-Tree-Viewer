# Security Policy

## Supported Versions

WPTV is currently validated against the following Wazuh versions:

| **Wazuh Version** | **OpenSearch Dashboards** | **WPTV Support** |
| ------------------ | ------------------------- | ---------------- |
| 4.14.7             | 2.19.5                    | ✅ Validated |
| 4.14.4             | 2.19.4                    | ✅ Validated |
| 5.x                | —                         | ❌ Not validated |
| < 4.14             | —                         | ❌ Not validated |

> **Compatibility note:** WPTV v2.1 was initially developed and validated with Wazuh 4.14.4, which uses OpenSearch Dashboards 2.19.4. Subsequent testing with Wazuh 4.14.7 identified an OpenSearch Dashboards version change to 2.19.5. The WPTV OSD plugin manifest must match the installed OpenSearch Dashboards version for the plugin to load correctly. See the README for the version-specific deployment requirements.

### Reporting a Vulnerability

We use **GitHub Security Advisories** to manage vulnerability reports. If you find a security vulnerability in WPTV, please:

1. Go to the **"Security"** tab of this repository.
2. Click **"Advisories"** and then **"Report a vulnerability"**.
3. Provide the vulnerability details and steps to reproduce.

This keeps the report private while we investigate and work on a fix.

**Please do not open a public Issue for security vulnerabilities.**
