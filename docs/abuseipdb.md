# AbuseIPDB

Open **Administration → Login security → AbuseIPDB**. Enter your AbuseIPDB API
key, or set `POSTPLUS_ABUSEIPDB_API_KEY` in the server environment. The key is
never returned by the administration API. Leaving its input empty preserves it;
the remove option deletes the saved key. An environment-provided key remains
available until removed from the service environment.

Settings are saved in the authentication database and apply immediately. All
features are disabled until configured and enabled by an administrator.

## Reputation tools and capacity

The panel supports `check`, `reports`, `blacklist`, `check-block`, `report`,
`bulk-report`, and `clear-address` using the [official API v2](https://docs.abuseipdb.com/).
It also offers `bulk-check` as a batch of up to 20 individual `check` requests;
the public API documentation does not define a separate bulk-check endpoint.
Every IP in this batch consumes the ordinary check allowance. A batch shares
a 20-second time budget and shows partial completion if the budget is exhausted.

Usage and capacity come from `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and
`X-RateLimit-Reset` response headers. An unobserved limit appears as **Unknown**,
not as an assumed account entitlement. The table refresh itself does not call
AbuseIPDB. Observed quotas and reputation caches are held in memory and are
refreshed after a restart. Quotas and access may differ from the account shown in a screenshot;
upgrade or account restrictions are returned by AbuseIPDB. Rate-limit responses
cause requests to back off until their retry/reset time.

For bulk reports, paste or upload CSV with `IP`, `Categories`, `ReportDate` and
`Comment` columns. `ReportDate` is optional. Quote fields that contain commas,
newlines or quotation marks. For example:

```csv
IP,Categories,ReportDate,Comment
203.0.113.10,18,2026-10-25T12:00:00Z,"Observed repeated failed sign-ins"
```

The example address is reserved for documentation. Use actual evidence for
actual reports. `clear-address` removes reports submitted by your account;
it does not remove other users' reports or unblock an IP locally.

## Automatic protection

Enable reputation blocking and choose the minimum confidence score, minimum
report count, report lookback, cache duration and temporary block duration.
Checks are triggered by failed sign-ins. The normal IP allowlist applies.
An unavailable reputation service does not itself create a block.

Enable automatic reporting separately and choose the local failure threshold,
categories and per-IP cooldown. Category `18` denotes brute force. Reports
contain the direct source IP, local failure counts and protocol; they omit
usernames, passwords and raw log lines. A high remote reputation score alone
does not generate a local abuse report. Cached checks and reporting cooldowns
reduce repeated requests; rate limits still depend on the account's allowance.

As with existing login protection, socket peer addresses are used. Configure
network topology accordingly when a reverse proxy is in front of PostPlus.

## Webmaster verification

Copy your domain's token from **AbuseIPDB → Webmaster Settings** into the
**Webmaster verification token** field and save. PostPlus serves the token at
`/abuseipdb-verification.html` on its public web interfaces. Point the domain
at this server and ensure HTTP or HTTPS on its standard port reaches PostPlus
(or proxy that exact path). Then use **Verify Domain Now** on AbuseIPDB.

Saving the token publishes the file; only AbuseIPDB can confirm domain ownership.
An empty token disables the public verification file. This file is public by
design and contains no API key.
