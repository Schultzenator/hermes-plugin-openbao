# hermes-openbao

An MIT Hermes Agent secret-source plugin for OpenBao and HashiCorp Vault.
It resolves explicit `bao://mount/path#key` references through the native Vault
HTTP API and hands the values back to Hermes's secret orchestrator. This is a
real runtime integration: token protection, KV v1/v2 selection, request
timeouts, HTTP error classification, provenance, and conflict handling are
provided by the plugin/framework rather than a prompt or skill.

## Install

Copy this directory to `~/.hermes/plugins/openbao/`, then enable it in Hermes:

```yaml
secrets:
  sources: [openbao]
  openbao:
    enabled: true
    vault_addr: https://vault.example.com
    version: auto
    env:
      OPENAI_API_KEY: bao://kv/factory/credentials/openai#api_key
      DATABASE_URL: bao://kv/factory/credentials/postgres#url
```

Provide only the bootstrap token through Hermes's normal environment/secret
routes (`HERMES_OPENBAO_TOKEN`). The plugin never reads `.env`, `auth.json`,
or another credential store, never writes `os.environ`, and never prompts.
`bao://` references use `#key` for a field; when a secret has exactly one
field, the key may be omitted. `version: auto` tries KV v2, then KV v1.

## Development

Run the smoke/unit suite from the repository root with the Hermes checkout on
the import path:

```bash
PYTHONPATH=../hermes-agent python3 -m pytest -q hermes-openbao/tests
```

The tests use a local in-process HTTP server and do not require OpenBao,
network access, or third-party plugin dependencies.

## Security disclosure

The plugin makes outbound HTTP(S) requests to the configured Vault/OpenBao
address and sends the bootstrap token in the standard `X-Vault-Token` header.
It keeps no secret cache and starts no background process. Use HTTPS for remote
backends. The catalog entry should pin a full commit SHA.

License: MIT.
