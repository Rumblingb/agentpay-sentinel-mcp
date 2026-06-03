<p align="center">
  <img src="assets/logo.png" width="80" alt="AgentPay">
</p>

# AgentPay Sentinel MCP

A watchdog MCP that validates every agent payment request against all 9 security checks before it executes — catching policy violations, replay attacks, amount tampering, revoked tokens, and budget overruns at call time.

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
| `sentinel_audit_transaction` | Run all 9 security checks; returns PASS/BLOCKED + SHA-256 audit hash | `token_hash`, `merchant_id`, `amount`, `current_spend`, `budget_cap` (required) · `nonce`, `token_id`, `approved_amount` (enable checks 7–9) |
| `sentinel_revoke_token` | Permanently revoke a token — all future audits with this `token_id` will BLOCK | `token_id`, `reason` |
| `sentinel_clear_nonce` | Remove a nonce from the replay store (for legitimate refunds/retries only) | `nonce` |
| `sentinel_verify_chain` | Verify a sequence of audit hashes forms an unbroken chain | `audit_hashes`, `expected_chain_root` |
| `sentinel_threat_model` | Simulate any named attack vector; returns severity, defence, and detection | `attack_vector`, `context` |

### All 9 checks run by `sentinel_audit_transaction`

| # | Check | What it catches | Param |
|---|-------|-----------------|-------|
| 1 | Token integrity | SHA-256 hash mismatch — forged tokens | `token_hash` |
| 2 | Budget enforcement | Spend exceeding cap | `current_spend`, `budget_cap` |
| 3 | Merchant allowlist | Payment to unlisted merchant | `allowlist` |
| 4 | Category restriction | Purchase in blocked category | `blocked_categories` |
| 5 | Expiry check | Expired token | `expires_at` |
| 6 | Rate limit | Too many calls per minute | `calls_this_minute` |
| 7 | **Amount mismatch** | Agent changed amount after human approved | `approved_amount` |
| 8 | **Replay attack** | Same nonce used twice (file-backed store) | `nonce` |
| 9 | **Revocation evasion** | Agent using a revoked token | `token_id` |

Checks 7–9 activate when the corresponding param is passed. State persists to `~/.sentinel/`.

### Attack vectors in `sentinel_threat_model`

`token_forgery` · `budget_overflow` · `replay_attack` · `amount_mismatch` · `revocation_evasion` · `merchant_spoof` · `expiry_bypass`

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
