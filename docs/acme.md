# Certificates from Let's Encrypt

PostPlus can request a TLS certificate directly from first-run setup or the administration website. Certificate requests run in the background; the page shows their status while domain validation takes place. No Certbot, Python process, shell script or external certificate client is required.

## Before requesting a certificate

Use a fully qualified DNS name that you control, such as `mail.example.com`. This name will appear in the certificate and should be the hostname people use in their browser and mail clients. IP addresses, wildcard names and `localhost` are not supported by this workflow.

Create an **A record** pointing the name at the server's public IPv4 address. If you publish an **AAAA record**, its IPv6 address must also reach the same challenge endpoint. Remove an incorrect AAAA record before requesting a certificate.

Allow inbound **TCP port 80** through the server firewall, router and hosting provider firewall. Let's Encrypt uses HTTP-01 domain validation: it reads a temporary file at `http://mail.example.com/.well-known/acme-challenge/<token>`. It always connects to public port 80; changing the administration or Webmail port does not change this requirement.

PostPlus starts a small temporary HTTP listener for validation. The default is IPv4 address `0.0.0.0`, port `80`. Another application must not already occupy that port. On systems that restrict ports below 1024, the PostPlus process performing issuance needs permission to bind port 80. The listener serves only the current domain challenge and closes when the request finishes or is cancelled.

If you already use a reverse proxy, route the exact challenge path to PostPlus while preserving the requested hostname. A custom embedded deployment can supply `AcmeOptions` with a different local challenge port and forward **public port 80** to it. This does not change the port that the CA uses. The stock web workflow uses the default listener.

## Request a certificate in the browser

1. Open first-run setup, or sign into the administration website and open server configuration.
2. Expand **Get a certificate from Let's Encrypt**.
3. Enter the certificate hostname and a contact email address you can receive mail at.
4. Select **Staging** for your first connectivity test. Its certificates are intentionally untrusted and are unsuitable for normal browser or mail access.
5. Select **Load certificate authority terms**, read the linked terms, and tick the agreement checkbox. Loading the terms does not create an account or request a certificate.
6. Select **Request certificate**. Keep the server running while validation completes. You can cancel a pending request from the same page.
7. After staging works, select **Production**, load and review its terms, and submit a production request.
8. When the production request succeeds, select **Use these certificate paths**. Review the TLS fields and save the configuration. First-run setup starts the services using the saved certificate. For an existing installation, **restart PostPlus manually** when convenient to load the new certificate.

Issuance writes certificate files only. It does not change the running services, replace the active certificate, save other server settings or restart PostPlus. On an existing installation, connections continue using the current settings until you restart. The first-run wizard starts normal services only after you save its configuration.

## Where files are stored

The web workflow stores ACME material in the `certificates` directory beside the configuration file. Staging and production use separate subdirectories:

```text
config/
  postplus.json
  certificates/
    production/
      account-key.pem
      mail.example.com-<request-id>/
        fullchain.pem
        private-key.pem
    staging/
      account-key.pem
      mail.example.com-<request-id>/
        fullchain.pem
        private-key.pem
```

`account-key.pem` identifies your ACME account and is reused for later requests in the same environment. `private-key.pem` belongs to one issued certificate; `fullchain.pem` contains the leaf certificate followed by its issuer chain. Each successful request gets a new directory, so previous certificates remain available for rollback.

PostPlus creates private files with owner-only permissions on Unix and an owner-and-SYSTEM ACL on Windows. Back up these files together with your configuration. Never publish private keys in the repository or expose the certificate directory as static web content. The API returns paths and expiry information; it never returns private key contents.

## Renewal

The page displays the certificate expiry returned by the CA. Request a replacement before the existing certificate expires, apply the new paths, save, then restart manually. The same account key is reused. This version does not schedule automatic renewal or automatic restarts.

Avoid repeated production requests while diagnosing network problems. Use staging first and follow [Let's Encrypt's rate limits](https://letsencrypt.org/docs/rate-limits/).

## Troubleshooting

| Message or symptom | What to check |
| --- | --- |
| Cannot listen for HTTP-01 | Port 80 may be occupied, or the process may lack permission to bind it. Check the local listener and firewall configuration. |
| HTTP-01 domain validation failed | Check public A/AAAA records, router forwarding, hosting-provider firewall rules and the `/.well-known/acme-challenge/` route. Requests must reach the server using the certificate hostname. |
| Issuance timed out | The overall request is bounded to five minutes by default. Correct the network problem before retrying. |
| Terms changed | Load and read the newly published terms, then explicitly agree before retrying. |
| Rate limit reached | Wait for the CA's limit to reset. Use staging for further tests. |
| Certificate chain cannot be verified | Check the machine's trusted CA roots and system clock. Production downloads and issued chains are validated; TLS verification is never disabled. |
| Browser distrusts a staging certificate | This is expected. Request a production certificate after the staging test succeeds. |
| New certificate is saved but clients see the old one | Apply and save the returned TLS paths, then restart PostPlus manually. |

## API and embedding reference

The authenticated administration routes are:

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/api/admin/acme/terms?directory=staging` | Read the CA's terms URL without accepting it. |
| POST | `/api/admin/acme/start` | Start a request after explicit consent. |
| GET | `/api/admin/acme/status?job_id=<id>` | Read progress and the final result; omit the ID for the latest request. |
| POST | `/api/admin/acme/cancel` | Request cancellation using `{"job_id":"<id>"}`. |

First-run setup uses the equivalent routes under `/api/setup/acme/` and requires its one-time setup credential. Administration mutations also require the existing session and CSRF protections.

The start request contains exactly:

```json
{
  "domain": "mail.example.com",
  "email": "operator@example.com",
  "directory": "staging",
  "agree_terms": true,
  "terms_of_service": "<exact HTTPS URL returned by the terms endpoint>"
}
```

Progress states are `queued`, `connecting`, `ordering`, `authorizing`, `finalizing`, `downloading`, `succeeded`, `failed` and `cancelled`. A successful result includes `tls_certificate`, `tls_private_key`, `expires_at`, `staging` and `restart_required`. A manager keeps its latest job in memory; completed certificate files persist across restarts. Only one request can run per manager.

The implementation uses RFC 8555 account and order resources, ES256 JWS requests, fresh replay nonces with bounded `badNonce` retries, POST-as-GET resource retrieval, HTTP-01 key authorization and a P-256 CSR with one DNS SAN. It verifies the issued key, DNS SAN, validity, server purpose and issuer signatures. Production certificates also require a chain to a trusted root. The production and staging directory origins are fixed; arbitrary directory URLs and cross-origin resource redirects are rejected.

All network requests and response sizes are bounded. Tests use an injected loopback-only mock CA that verifies JWS signatures and CSRs, performs the real local HTTP challenge, and signs temporary test certificates. Browser requests cannot enable this test transport or supply a CA URL.
