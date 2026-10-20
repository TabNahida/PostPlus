# DNS recommendations and diagnostics

Open **Administration → Domains → Manage domain → DNS** for the selected
mail domain's DNS records and checks. The adjacent **Webmail address** and
**TLS certificates** tabs manage its browser hostname and certificates.
Server settings still controls listener addresses, ports and delivery mode.
DNS lists A, optional AAAA, MX, SPF, DKIM, DMARC, reverse DNS (PTR),
and the optional SRV discovery records for enabled secure mail services.
Matching records remain in the list, so it is also a reference for records
that have already been published.

The DNS tab uses the selected active or pending mail domain and the **saved**
mail hostname, Webmail binding and ports. Editing expected values or loading
recommendations does not publish DNS, generate a key or restart services.
After changing records at your provider, click **Test DNS and connectivity**.
The domain check saves its expected values and server-generated verification
evidence with the current configuration revision. **Reload DNS recommendations**
picks up saved settings and a newly configured DKIM public key.

Each mail domain has an MX pointing to the shared `mail_hostname`. A separate
Webmail binding can serve `user@a.com` at `mail.a.com`; this does not change the
mailbox suffix or MX target. The DNS tab includes A/AAAA guidance for that
browser hostname. It also shows configured administration and shared-Webmail
hostnames under the primary domain and under matching hosted suffixes. Address
records for identical hostnames are deduplicated. Portal records are advisory:
domain activation requires a matching MX and a public address for the mail
server, while browser DNS and TLS still need separate setup.

Use **DNS → DKIM public DNS record** to generate/load the selected domain's
public record and to manage the signing selector. The key and selector are
shared by hosted domains; publish the public record separately under
`<selector>._domainkey.<domain>` for every sending domain. Changing the selector
requires updating those records across all sending domains. Key generation
does not publish DNS or enable direct delivery by itself.

Enter your actual public IPv4/IPv6 addresses under **Expected DNS values**
to compare them with public DNS. Direct delivery prepares an SPF policy for
those addresses. With no expected addresses, the initial direct-delivery
recommendation is `v=spf1 mx -all`; review it against the real outgoing IPs,
especially with NAT or multiple senders. Enter an existing SPF/DMARC policy
or your relay's real public DKIM record if you want to check those values.
Without expected addresses, published public A/AAAA values are shown as
**Published — verify the address**, rather than claimed as a verified match.
Absent optional IPv6 is distinguished from a failed DNS query.
Portal A/AAAA records use those same expected addresses. If HTTPS terminates
at a different reverse-proxy address, review the portal's observed addresses
against that deployment separately.

Publish one SPF policy at the mail domain and one DMARC policy at `_dmarc`.
Use direct A/AAAA records for the MX target, with DNS-only mode. PTR is set
through the VPS or IP provider, not as a TXT record in the domain's DNS zone.
The server checks PTR for the public addresses returned for the mail host.
SRV values use priority, weight, port, target; for example:
`0 1 993 mail.example.com.`.

Connectivity checks always include public SMTP port **25**, even when the
saved local SMTP listener is a custom port, and also check enabled mail
listeners and Webmail. Only numeric public addresses returned by the bounded
public resolver are used; private/reserved addresses are rejected. Browser
input cannot select an arbitrary host, port, resolver, or deadline. DNS and
TCP operations share a short total time budget.

These are **server-originated TCP checks**. A NAT gateway may block its own
public address from the inside; an external firewall can block other networks
even when the server-originated check succeeds. The result does not verify
TLS certificates, Internet inbound reachability, outbound port 25, DKIM
signatures, message delivery, or sender reputation.

Use **TLS certificates** to request a Let's Encrypt certificate for a selected
hostname or attach existing PEM paths. PostPlus chooses hostname-specific
certificates through TLS SNI and retains a default certificate for clients
without SNI. HTTP-01 issuance requires the selected hostname's public A/AAAA
and port 80 to reach the challenge listener. Issuance fills the file paths;
save the hostname certificate to apply it. Existing default TLS paths are
preserved when saving a hostname override. Renew the default explicitly under
the primary domain's **Default certificate for mail services** controls.
DNS success is not certificate
issuance or a certificate-trust check. See the [TLS configuration reference](configuration.md#tls-and-account-security).

## Administration API

Domain management uses these endpoints. Administrator sessions require CSRF
for POST; Bearer keys require the listed permission.

| Endpoint | Contract | Permission |
| --- | --- | --- |
| POST `/api/admin/domains/preview` | `{"domain":"a.com","dns":{}}`; recommendations without writes or network access. | `config:read` |
| POST `/api/admin/domains/check` | `{"revision":"…","domain":"a.com","dns":{}}`; checks records and saves verification evidence for an existing active/pending domain. | `config:write` |
| POST `/api/admin/dkim` | `{"domain":"a.com","selector":"postplus"}`; prepares/reuses the key and returns its public DNS record. | `config:write` |

Optional `dns` fields are strings: `ipv4`, `ipv6`, `spf`, `dkim_name`,
`dkim_type` (`TXT` or `CNAME`), `dkim_value`, and `dmarc`. The server supplies
hostnames, ports, resolver and transport settings. The preview returns
`webmail_hostname` alongside the existing mail `hostname`, `expected` and
`records`. The check response includes the same report under `dns`, plus a
new configuration `revision`, domain `record` and `restart_required`.

Records include `id`, `type`, `name`, `value`, `status`, and `observed`;
checked reports also include `checked_at`, `resolver`, `connectivity`, and
`limitations`. Browser-address record IDs are `webmail-a`/`webmail-aaaa`,
`admin-a`/`admin-aaaa`, and `shared-webmail-a`/`shared-webmail-aaaa`, with matching
`purpose` values `webmail`, `admin`, and `shared-webmail`. All have
`required: false`. They follow public DNS aliases when checking portal
addresses; MX targets still require direct A/AAAA records. The connectivity
section probes the configured mail-server address and service ports, not a
separate portal reverse proxy.

The older saved-server diagnostic endpoints remain available with
`config:read` (or an administrator session; POST uses normal CSRF protection):

- `GET /api/admin/dns` returns all recommendations and expected-value defaults
  using the saved configuration. It performs no network requests or writes.
- `POST /api/admin/dns/check` checks recommendations and public service
  connectivity. An empty JSON object checks the saved server as-is.

An optional `domain` selects an active hosted domain in either endpoint;
GET uses a query parameter. POST accepts the same diagnostic expectation
strings directly in its body. These older endpoints do not add portal
records or save domain-activation evidence. Use the domain endpoints for
the complete domain-management workflow.

The first-run setup DNS check remains limited to A/AAAA, MX, SPF, DKIM, and
DMARC. The broader saved-server diagnostics are available after setup.
