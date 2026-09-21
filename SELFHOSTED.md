# Self-hosted passd integration

This branch carries the v0.3.1 self-hosted adapter while intentionally leaving Proton's normal production client and entitlement checks unchanged.

The added `pass-cli-local` executable talks to `passd` over its local authority protocol. The preferred agent path is typed capabilities such as `openrouter.infer`, not arbitrary vault/item lookup.

The credential store, HITL authority implementation, security validation, benchmark kernel, and remote-custody threat model live in the separate `kvnloo/passd` repository.
