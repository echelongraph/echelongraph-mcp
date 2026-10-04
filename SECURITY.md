# Security policy

## Reporting a vulnerability

Please report a vulnerability in this MCP server privately, by email to
**support@echelongraph.io**. That is the contact EchelonGraph publishes for security
reports on its [responsible-disclosure page](https://echelongraph.io/responsible-disclosure)
and in its [security.txt](https://echelongraph.io/.well-known/security.txt).

Please do not open a public GitHub issue for a vulnerability.

A useful report says:

- the package version (the server reports it in the MCP handshake, and it is in
  `package.json`);
- what an attacker can do, and what they need first (for example a malicious API base URL, a
  crafted tool argument, or a crafted API response);
- the steps or a proof of concept that shows it.

We support coordinated disclosure: tell us before you publish, and we will agree a reasonable
remediation window with you. The full policy is at
<https://echelongraph.io/responsible-disclosure>.

## Supported versions

Only the latest version published to npm
([`echelongraph-mcp@latest`](https://www.npmjs.com/package/echelongraph-mcp)) receives
security fixes. A fix ships as a new version; npm versions are immutable, so an older version
is never changed in place. Upgrade to the latest version to receive a fix.

## Scope

This repository holds the MCP server only: the stdio server that calls EchelonGraph's public
API, and its HTTP entrypoint, which EchelonGraph runs as the hosted endpoint
`https://mcp.echelongraph.io/mcp`. A vulnerability in the EchelonGraph API or website (`echelongraph.io`,
`app.echelongraph.io`) is also welcome at the same address.
