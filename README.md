# Sky Ecosystem — Bug Bounty Reports (Immunefi)

> immunefi.com/bug-bounty/sky/scope/#top

## Findings Summary

| # | Bug | Severity | Scope |
|---|-----|---------|-------|
| 01 | GITHUB_TOKEN Exposed to Browser Bundle | **Critical** (conditional) | Web & Applications |
| 02 | DaiUsds Token Redirect via `usr` Parameter | **Critical** | Smart Contracts |

---

### Finding 01 — GITHUB_TOKEN Exposure (Web & Applications)

**File:** `01-GITHUB_TOKEN-exposure.md`

| | |
|---|---|
| **Severity** | Critical (conditional — depends on token scope) |
| **Scope** | Web & Applications — `vote.sky.money` |
| **Asset** | `governance-portal-v2/next.config.js` lines 53–56 |
| **Impact** | GitHub token hardcoded into browser JS bundle → extractable via DevTools |
| **In-Scope Category** | "Retrieve sensitive data... blockchain keys" (if write-scope token) |

**⚠️ Conditional:** Severity is Critical only if the `GITHUB_TOKEN` has write access. If read-only, the finding may be rejected as "non-sensitive environment variable."

---

### Finding 02 — DaiUsds Token Redirect (Smart Contracts)

**File:** `02-DaiUsds-token-redirect.md`

| | |
|---|---|
| **Severity** | Critical |
| **Scope** | Smart Contracts — `DaiUsds.sol` |
| **Contract** | `0x3225737a9Bbb6473CB4a45b7244ACa2BeFdB276A` (mainnet) |
| **Impact** | `daiToUsds(attacker, amount)` sends USDS to attacker, not msg.sender |
| **In-Scope Category** | "Malicious interactions with already-connected wallet" |

**Root cause:** `daiToUsds(address usr, uint256 wad)` exits tokens to `usr` parameter — no domain binding, no `msg.sender` check.

---

*Audited by: Hermes Agent + Codex CLI*  
*Date: 2026-05-19*