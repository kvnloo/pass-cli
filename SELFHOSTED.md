# Self-hosted passd integration

This overlay intentionally leaves Proton's normal production client and entitlement checks unchanged.

The added `pass-cli-local` executable talks to `passd` over its local authority protocol. v0.3's preferred agent path is typed capabilities, not arbitrary vault/item lookup.

## Scope after the sensitive-data architecture update

This fork remains **credential-plane only**.

It should not grow commands for:

- tax PDFs or bank statements;
- OCR/search/document indexing;
- SSN/passport document storage;
- raw authenticated-browser state;
- local-model PII processing.

Those belong in a separate private execution zone using an existing document system and local/private workers. `passd` may supply credentials to that zone through destination-bound capabilities, but the Proton CLI adapter should not become a document or PII API.

For an agent, the preferred abstraction remains:

```text
openrouter.infer
github.api
bank.login
```

not:

```text
pass://...
paperless://...
/path/to/tax-return.pdf
```

The broader private-execution design is documented in `kvnloo/passd/PRIVATE_EXECUTION.md`.

The full trust model, remote-custody requirement for hostile-root resistance, protocol, security tests, and latency receipts live in [`kvnloo/passd`](https://github.com/kvnloo/passd). This fork overlay is tested against the hardened passd v0.3.1 baseline.
