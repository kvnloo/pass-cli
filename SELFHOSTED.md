# Self-hosted passd integration

This overlay intentionally leaves Proton's normal production client and entitlement checks unchanged.

The added `pass-cli-local` executable talks to `passd` over its local authority protocol. v0.3's preferred agent path is typed capabilities, not arbitrary vault/item lookup.

The full trust model, remote-custody requirement for hostile-root resistance, protocol, security tests, and latency receipts live in [`kvnloo/passd`](https://github.com/kvnloo/passd). This fork overlay is tested against the hardened passd v0.3.1 baseline.
