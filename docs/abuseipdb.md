# AbuseIPDB

Open **Administration → Security → AbuseIPDB**. Enter your AbuseIPDB API
key in its separate card, or set `POSTPLUS_ABUSEIPDB_API_KEY` in the server
environment under the advanced key-source option. The key is never returned by
the administration API. After saving, its card shows **API key configured**;
choose **Modify API key** to replace or remove it. Cancel clears the draft.
The Webmaster token has a separate card and save action. Policy, token and
credential saves only update their own fields.
An environment-provided key takes precedence while the configured variable is
set on the server. Removing the saved key does not remove an environment key.

Settings are saved in the authentication database and apply immediately. All
features are disabled until configured and enabled by an administrator.

## Reputation tools and capacity

The panel supports `check`, `reports`, `blacklist`, `check-block`, `report`,
`bulk-report`, and `clear-address` using the [official API v2](https://docs.abuseipdb.com/).
It also offers `bulk-check` as a batch of up to 20 individual `check` requests;
the public API documentation does not define a separate bulk-check endpoint.
Every IP in this batch consumes the ordinary check allowance. A batch shares
a 20-second time budget and shows partial completion if the budget is exhausted.

Saving an API key automatically refreshes observed capacities with four small
read-only requests: `check`, `reports`, `blacklist`, and `check-block`. These use
the fixed reference address `8.8.8.8`, rather than the server's address. Each
request consumes that endpoint's allowance. Use **Refresh capacity** to repeat
this explicitly; a 60-second cooldown prevents accidental repeated probes.
Opening or refreshing the panel only reads the saved view and consumes no
upstream requests. Discovery works while automatic protection is disabled.

Usage and capacity come from the official `X-RateLimit-Limit`,
`X-RateLimit-Remaining`, and `X-RateLimit-Reset` response headers. AbuseIPDB does
not document an account-wide quota endpoint. The report, bulk-report and
clear-address rows remain **Unknown** until an actual operation returns their
headers; capacity discovery never submits or deletes a report. No account tier
is guessed from other endpoint limits. An upstream failure leaves the saved
key intact and is shown separately from credential-save status.

Observed quotas and reputation caches are held in memory and refreshed after a
restart. Rate-limit responses back off until their retry/reset time. A key
change clears observations; policy and Webmaster token changes retain them.

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
Time fields accept seconds, minutes, hours and days; report lookback accepts
days or weeks. Values must convert to a whole second or whole day within the
displayed limits. Switching units preserves the exact stored value.

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
