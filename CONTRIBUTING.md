# Contributing to echelongraph-mcp

Thank you for helping. This server is MIT-licensed (see [LICENSE](LICENSE)), and contributions are accepted under the same licence.

## How this repository is published

This repository is published from EchelonGraph's main codebase at each release: every tag `vX.Y.Z` carries exactly the code of the npm release `echelongraph-mcp@X.Y.Z`, built by this repository's release workflow with a provenance attestation. Because the next release replaces the tree, a pull request is not merged here directly: we review it, apply the change in our main codebase with credit to you, and it ships in the next release.

## Reporting a bug or asking for a feature

Open an issue, and include:

- the `echelongraph-mcp` version (the `serverInfo.version` your client shows, or the version in your `npx` command) and whether you use the npm package or the hosted endpoint `https://mcp.echelongraph.io/mcp`;
- the tool you called, its arguments, and the answer you got (redact anything private);
- what you expected instead.

**Security issues are not filed here.** Report them privately as [SECURITY.md](SECURITY.md) describes.

## Proposing a change

1. Fork the repository and make your change on a branch.
2. Run `npm ci`, `npm run build` and `npm test`. All tests must pass.
3. Keep each tool's description and output accurate: a description or note states only what the server and the EchelonGraph API actually do. The tests check many of these statements; if you change one, change its test with it.
4. Open a pull request that says what the change does and why, and how you tested it.

## Code of conduct

Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
