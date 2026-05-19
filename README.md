# Sky Ecosystem — Bug Bounty Reports (Immunefi)

> Web & Applications scope only | immunefi.com/bug-bounty/sky/scope/#top

## Findings

| # | Bug | Severity | Asset |
|---|-----|---------|-------|
| 01 | GITHUB_TOKEN Exposed to Browser Bundle | Critical | vote.sky.money |
| 02 | DaiUsds Token Redirect via Malicious Frontend | HIGH | app.sky.money |

---

### Finding 01 — GITHUB_TOKEN Exposure

**File:** `01-GITHUB_TOKEN-exposure.md`

The `next.config.js` in `governance-portal-v2` explicitly exposes `GITHUB_TOKEN` to the browser bundle via Next.js `env` config. Any token set at build time gets hardcoded into the JS bundle and is extractable via browser DevTools.

**Impact:** Attacker extracts token → gains API access to sky-ecosystem GitHub repositories.

---

### Finding 02 — DaiUsds Token Redirect

**File:** `02-DaiUsds-token-redirect.md`

The `DaiUsds` contract's `daiToUsds(address usr, uint256 wad)` and `usdsToDai(address usr, uint256 wad)` functions send output tokens to the `usr` parameter — **not** `msg.sender`. This enables a malicious frontend to redirect token flows.

**Impact:** Phishing site calls `daiToUsds(attacker_address, amount)` → user approves DAI spend → USDS ends up at attacker address.

---

*Audited by: Hermes Agent + Codex CLI*  
*Date: 2026-05-19*
