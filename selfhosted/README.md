# pass-cli-local v0.3 (passd v0.3.1)

Thin Proton-style companion CLI for the local `passd` authority/capability broker. It does not contain Proton vault cryptography and does not emulate Proton's cloud API.

## Preferred agent workflow

Trusted/custody side:

```bash
pass-cli-local capability put-http openrouter.infer \
  --backing-uri 'pass://Personal/OpenRouter/password' \
  --host openrouter.ai \
  --method POST \
  --path-prefix /api/v1/chat/completions \
  --inject-header Authorization \
  --inject-prefix 'Bearer '

pass-cli-local agent create hermes --expiration 1d
```

Agent side:

```bash
export PASSD_AGENT_TOKEN='pda_...'
export PASSD_AGENT_REASON='Need inference for current task'

pass-cli-local capability list
pass-cli-local capability request openrouter.infer \
  --method POST --path /api/v1/chat/completions --uses 1 --expiration 5m
```

Human/custody side:

```bash
pass-cli-local access pending
pass-cli-local access approve req_... --uses 1 --expiration 2m
```

Agent side:

```bash
pass-cli-local capability invoke openrouter.infer \
  --method POST --path /api/v1/chat/completions \
  --body '{"model":"...","messages":[]}'
```

The public capability record contains no vault, item, field, or `pass://` backing URI.

## Legacy commands

`vault`, `item`, `resolve`, `access request pass://...`, and `broker-http` remain for migration/admin compatibility. New automated workflows should use typed capabilities.

Backend source: https://github.com/kvnloo/passd (tested against v0.3.1).
