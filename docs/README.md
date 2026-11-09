# Runtime documentation

- [Architecture and trust boundaries](architecture.md)
- [Artifact formats and verification](artifact-formats.md)
- [Self-hosting the notary](self-hosting.md)
- [Clustered daemon operation](cluster-operations.md)
- [Notary key lifecycle](notary-key-lifecycle.md)

The desktop app's local service publishes its exact REST contract at
`http://127.0.0.1:8788/openapi.json`; the server's contract is committed at
`crates/capture-server/openapi.json`. Agents call the local service through its
MCP endpoint, `http://127.0.0.1:8788/mcp`.
