# AgentPay Sentinel MCP 🔐

Autonomous security guardrails for AI agent payments. Red team attack simulation + blue team defense = adversarial co-evolution.

Part of the AgentPay implementation layer — the governance fabric that makes agent payments enterprise-grade.

## What It Does

AgentPay Sentinel runs 9 security checks on every agent transaction:

| # | Check | What It Blocks |
|---|-------|---------------|
| 1 | Token Integrity | Forged/replayed scoped tokens |
| 2 | Budget Enforcement | Spend exceeding budget cap |
| 3 | Merchant Allowlist | Payments to unauthorized merchants |
| 4 | Category Restriction | Purchases in blocked categories |
| 5 | Expiry Check | Expired tokens |
| 6 | Rate Limiting | Transaction velocity abuse |
| 7 | Amount Verification | Amount changed after approval |
| 8 | Replay Detection | Duplicate transactions |
| 9 | Chain Integrity | Tampered audit logs |

## Tools

- `sentinel_audit_transaction` — Full 9-check audit with SHA-256 hash
- `sentinel_verify_chain` — Verify audit chain integrity
- `sentinel_threat_model` — Red-team simulation against guardrails

## Inspired By

Project ARES — autonomous adversarial security operations. AgentPay Sentinel applies the same red-team/blue-team co-evolution pattern to payment governance.

## Pricing

- **Free**: 50 audits/month
- **Pro**: $19/mo unlimited audits + threat modeling

[![AgentPay Sentinel](https://img.shields.io/badge/AgentPay-Sentinel-ff2d95)](https://agentpay.so)
