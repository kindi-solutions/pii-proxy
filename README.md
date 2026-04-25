# pii-proxy

A GDPR-compliant PII sanitization proxy for [Claude Code](https://claude.ai/code). Intercepts all outbound API requests, strips personally identifiable information using [Microsoft Presidio](https://microsoft.github.io/presidio/), then forwards sanitized requests to Anthropic. Responses pass through unchanged.

Built for Swedish companies but works for any team that needs to prevent PII from leaving their network.

```
Claude Code  →  pii-proxy (localhost:8080)  →  api.anthropic.com
                └─ Presidio detects & replaces PII
                   emails, phones, personnummer, secret keys, ...
```

> **Note:** Claude's responses will reference placeholders like `<PERSON_1>` instead of real names — this is the intentional trade-off for request-only sanitization.

---

## Quick Start

**1. Start the proxy**

```bash
git clone https://github.com/your-org/pii-proxy
cd pii-proxy
touch audit.jsonl request_debug.jsonl sanitizer.log   # create log files before mounting
docker-compose up --build
```

**2. Point Claude Code at the proxy**

```bash
export ANTHROPIC_BASE_URL=http://localhost:8080
claude
```

Or add permanently to your project's `.claude/settings.local.json`:

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://localhost:8080"
  }
}
```

**3. Open the dashboard**

Visit [http://localhost:8080/dashboard](http://localhost:8080/dashboard) to see live sanitization statistics.

---

## Supported PII Types

### Swedish PII
| Entity | Description |
|---|---|
| `SE_PERSONNUMMER` | Personal identity numbers (YYYYMMDD-XXXX, with Luhn validation) |
| `SE_SAMORDNINGSNUMMER` | Coordination numbers (day field +60) |
| `SE_ORGANIZATION_NUMBER` | Swedish org numbers (3rd digit ≥ 2, Luhn validated) |
| `SE_POSTAL_CODE` | Postal codes (context-aware) |

### Standard PII
| Entity | Description |
|---|---|
| `EMAIL_ADDRESS` | Email addresses |
| `PHONE_NUMBER` | Phone numbers |
| `PERSON` | Names (requires spaCy NER — see [Memory-efficient mode](#memory-efficient-mode)) |
| `LOCATION` | Locations (requires spaCy NER) |
| `CREDIT_CARD` | Credit card numbers |
| `IBAN_CODE` | IBAN bank account numbers |

### Secret Keys
| Entity | Examples |
|---|---|
| `SECRET_KEY` | AWS access keys (`AKIA...`), GitHub tokens (`ghp_`, `gho_`, `ghs_`), Stripe/OpenAI (`sk-`, `pk-`), Bitbucket (`ATBB...`), Sentry DSNs |


### Memory-efficient mode

By default, `PERSON` and `LOCATION` are not enabled. When neither is configured, the proxy loads only a small spaCy model (~50 MB) instead of the full NER models (~1.2 GB). Add them back to `entities` if you need name/location detection.

---

## Dashboard

The built-in dashboard at `http://localhost:8080/dashboard` shows:

- Total requests proxied vs. requests with PII detected
- Entity type breakdown (Swedish PII and secret keys shown separately)
- Last 10 sanitized messages — before and after, side by side

---

### What This Proxy Does

- Sanitizes **outbound requests only** — PII is stripped before leaving your network
- Does **not** scan or modify Anthropic's responses
- Does **not** store or transmit original PII values (audit log records entity types and counts only, not values — controlled by `log_original_values: false` in `config.yaml`)
- Does **not** perform de-anonymization — placeholders like `<PERSON_1>` are never reversed

### What This Proxy Does Not Protect Against

- Content in **Anthropic's responses** that happens to echo back PII
- PII in **tool call results** that the model generates itself
- Configuration mistakes (e.g. setting `log_original_values: true` in production)
- Secrets hardcoded in your codebase that pass through as non-matching patterns

### Sensitive Files

The following files are excluded from version control via `.gitignore` and should never be committed:
- `*.jsonl` — audit and request debug logs may contain message content
- `*.log` — application logs
- `.claude/settings.local.json` — may contain API keys or proxy URLs
- `.env` — environment variable files

---

## License

MIT — see [LICENSE](LICENSE).
