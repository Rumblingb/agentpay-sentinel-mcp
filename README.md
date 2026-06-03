# AgentPay Sentinel MCP

A watchdog MCP that validates every agent payment request against security checks before it executes — catching policy violations, replay attacks, and budget overruns at call time.

**Currently enforced:** 6 checks run on every `sentinel_audit_transaction` call. 9 attack vectors are defined in the threat model framework; amount-mismatch, replay detection, and revocation evasion are modeled in `sentinel_threat_model` but not yet wired into the live audit path.

## What your agent can do

- Run a pre-flight audit on any payment transaction before executing it — get PASS or BLOCKED with the specific check that failed
- Validate token integrity: confirms the SHA-256 hash matches the expected `merchant_id:amount` binding, catching forged or tampered tokens
- Enforce budget caps: rejects transactions where `current_spend + amount > budget_cap` and returns exact remaining budget
- Check merchant allowlist membership and block purchases in restricted categories
- Verify token expiry and rate limits before the payment fires
- Simulate known attack vectors (token forgery, budget overflow, replay, merchant spoof, expiry bypass) and get the specific defense mechanism and detection method for each

## Installation

**Requires:** Python 3.10+, `mcp` package.

```bash
pip install mcp
```

**Claude Desktop** — add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "agentpay-sentinel": {
      "command": "python",
      "args": ["/absolute/path/to/agentpay-sentinel-mcp/server.py"]
    }
  }
}
```

**Cursor** — add to `.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "agentpay-sentinel": {
      "command": "python",
      "args": ["/absolute/path/to/agentpay-sentinel-mcp/server.py"]
    }
  }
}
```

## Tool Reference

| Tool | Description | Key params |
|------|-------------|------------|
| `sentinel_audit_transaction` | Run 6 security checks on a transaction; returns PASS/BLOCKED + SHA-256 audit hash | `token_hash`, `merchant_id`, `amount`, `current_spend`, `budget_cap`, `allowlist`, `category`, `blocked_categories`, `expires_at`, `calls_this_minute`, `max_calls_per_minute` |
| `sentinel_verify_chain` | Verify an ordered list of audit hashes forms an unbroken chain | `audit_hashes` (array), `expected_chain_root` (optional) |
| `sentinel_threat_model` | Simulate a named attack vector; returns severity, defense mechanism, and detection method | `attack_vector`, `context` |

### Checks run by `sentinel_audit_transaction`

| # | Check | What it catches |
|---|-------|-----------------|
| 1 | Token integrity | SHA-256 hash mismatch — forged or replayed tokens |
| 2 | Budget enforcement | `current_spend + amount > budget_cap` |
| 3 | Merchant allowlist | Payment to an unlisted merchant |
| 4 | Category restriction | Purchase in a blocked category |
| 5 | Expiry check | Expired token (ISO timestamp comparison) |
| 6 | Rate limit | `calls_this_minute > max_calls_per_minute` |

### Attack vectors supported by `sentinel_threat_model`

`token_forgery`, `budget_overflow`, `replay_attack`, `merchant_spoof`, `expiry_bypass`

## Security

`sentinel_audit_transaction` returns an advisory verdict — it does not intercept network traffic. Your agent is responsible for calling it before executing a payment and halting on BLOCKED. The audit hash returned is a SHA-256 digest of all check results, giving you a tamper-evident record of each pre-flight decision.

## Pricing

| Plan | Price | Included |
|------|-------|----------|
| Free | $0 | 50 audits/month |
| Pro | $19/month | Unlimited audits + threat model simulations |

[Upgrade to Pro](https://agentpay.so)

## License

MIT — AgentPay Labs. Source: [github.com/Rumblingb/agentpay-sentinel-mcp](https://github.com/Rumblingb/agentpay-sentinel-mcp)
