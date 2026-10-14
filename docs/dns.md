# DNS recommendations and diagnostics

Administration → Server settings has separate **Network** and **DNS** groups.
Network controls listener addresses and ports and provides client connection
settings. DNS lists A, optional AAAA, MX, SPF, DKIM, DMARC, reverse DNS (PTR),
and the optional SRV discovery records for enabled secure mail services.
Matching records remain in the list, so it is also a reference for records
that have already been published.

The DNS group uses the **saved** server domain, mail hostname, and ports.
Editing DNS expected values does not save configuration, generate a key,
restart services, or change a DNS provider's records. After changing records
at your provider, click **Test DNS and connectivity** independently of
**Save settings**. **Reload DNS recommendations** picks up saved configuration
and a newly configured DKIM public key.

Enter your actual public IPv4/IPv6 addresses under **Expected DNS values**
to compare them with public DNS. Direct delivery prepares an SPF policy for
those addresses. With no expected addresses, the initial direct-delivery
recommendation is `v=spf1 mx -all`; review it against the real outgoing IPs,
especially with NAT or multiple senders. Enter an existing SPF/DMARC policy
or your relay's real public DKIM record if you want to check those values.
Without expected addresses, published public A/AAAA values are shown as
**Published — verify the address**, rather than claimed as a verified match.
Absent optional IPv6 is distinguished from a failed DNS query.

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

## Administration API

Both diagnostic endpoints require the `config:read` API key permission
(or an administrator session; POST uses the normal CSRF protection).

- `GET /api/admin/dns` returns all recommendations and expected-value defaults
  using the saved configuration. It performs no network requests or writes.
- `POST /api/admin/dns/check` checks recommendations and public service
  connectivity. An empty JSON object checks the saved server as-is.

Optional POST fields are strings: `ipv4`, `ipv6`, `spf`, `dkim_name`,
`dkim_type` (`TXT` or `CNAME`), `dkim_value`, and `dmarc`. Hostnames, domain,
ports, and transport settings are supplied by the server. Records include
`id`, `type`, `name`, `value`, `status`, and `observed`; checked reports also
include `checked_at`, `resolver`, `connectivity`, and `limitations`.

The first-run setup DNS check remains limited to A/AAAA, MX, SPF, DKIM, and
DMARC. The broader saved-server diagnostics are available after setup.
