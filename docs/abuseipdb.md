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

### Default plan for Standard accounts

The [official Standard daily allowances](https://docs.abuseipdb.com/#api-daily-rate-limits)
are 1,000 checks, 1,000 reports and 5 blacklist requests. PostPlus defaults to:

| Work | Default plan | Headroom |
| --- | --- | --- |
| Full confidence-100 blacklist | Every 6 hours; automation stops after 4 local blacklist requests in the UTC day | At least 1 of the 5 requests |
| Individual reputation checks | On an actual failed sign-in, at most 800 local requests per UTC day; new configurations cache an IP for 24 hours | At least 200 of 1,000 requests |
| Abuse reports | Only observed local failures; at most 800 local requests per UTC day, with per-IP cooldown | At least 200 of 1,000 requests |

Every blacklist request counts, including the capacity probe made after saving a
key and explicit manual queries. Thus a key probe normally leaves at most three
scheduled full refreshes that UTC day. Automatic work also stops when observed
provider remaining quota reaches 20% of its limit (at least one request). Explicit
manual tools may use this reserve but still obey provider rate limits. Budgets
are configurable for other plans; PostPlus never guesses your subscription.

The automatic plan table shows **local reservations**, separately from the API's
observed usage. A request reserves its local count before contacting AbuseIPDB;
failed or interrupted requests are conservatively counted. Counts, successful
full-list refresh times, and the complete list survive restarts in the private
authentication database. Changing a key does not reset the installation's daily
counts, since a replacement key can belong to the same account. Calls made by
other software are reflected only when the provider returns fresh quota headers.

Blacklist refresh runs only while AbuseIPDB, automatic blocking and the dedicated
blacklist option are enabled. Its request uses `confidenceMinimum=100` and
`limit=10000`, compatible with Standard accounts. Only a successful full scheduled
response replaces the security cache; small manual queries and capacity probes
never replace it. The full cache expires after 24 hours and is tied to its key.
Cached blacklist membership is checked locally before new authentication; no
external call blocks admission. Individual checks still require both your chosen
confidence score and minimum report count. Blacklist membership has a separate
rule because its response does not include report counts; PostPlus invents none.

Existing explicitly saved cache durations remain unchanged. Reports, check-block,
bulk reports and report deletion are not periodically invoked. Failed scheduled
refreshes back off, retain an unexpired valid cache and respect the durable daily
budget and any provider rate limit.

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
