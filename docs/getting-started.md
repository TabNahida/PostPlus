# Getting started with PostPlus

[中文入门指南](getting-started.zh-CN.md) · [Configuration reference](configuration.md) · [Back to README](../README.md)

This guide takes you from a fresh build to two local accounts exchanging mail. Later sections explain remote administration, a real domain, TLS, an outbound relay, and maintaining the installation.

## 1. Build and start

Install [xmake](https://xmake.io/) 2.9.8 or newer and a C++20 toolchain:

| Operating system | Compiler prerequisite |
| --- | --- |
| Windows | Visual Studio 2022 or newer, **Desktop development with C++** workload and Windows SDK |
| Linux | GCC 12 or newer, or a recent Clang toolchain with C++20 coroutines; standard development tools such as Git and Make |
| macOS | Xcode Command Line Tools; install with `xcode-select --install` if needed |

Open a terminal in the PostPlus repository and run:

```sh
xmake f -m release -y
xmake build -y
xmake run postplus
```

The first build downloads and builds dependencies, so it can take longer than later builds. The server runs until you press **Ctrl+C**. Keep that terminal open while you use the web interfaces. You do not need a Python launcher or a separately installed web server.

If you already have a built distribution, keep the launcher, every `postplus-*` service executable, and the `web` directory together. Run `postplus` (`postplus.exe` on Windows) from that directory. Use `--config` to select a configuration elsewhere; the parent directory must be writable by the server account.

## 2. Open and unlock setup

On an unconfigured installation, an interactive terminal first asks whether setup should listen on `127.0.0.1` (local access) or `0.0.0.0` (remote access). Choosing remote access also asks for the server hostname or IP used by your browser. The terminal then prints a **setup required** notice, a browser address, and a **one-time setup password**. The normal local address is:

```text
http://127.0.0.1:8081/
```

Open the address on the same computer that runs PostPlus. Enter the password printed by that running process to unlock setup. Do not substitute an email password or invent a value. If you restart PostPlus before finishing setup, use the newly printed password.

The setup password only authorizes this setup session. In the next step you create a separate, permanent administrator password. The setup password is not the password for Webmail and is not the internal service credential.

All pages start in English. Use the language selector to switch to **简体中文**; the browser remembers the choice.

### An existing configuration

The default file is `config/postplus.json`. There is no need to copy the example before using the wizard. A missing file, or an uninitialized sample with no service-token file path, no active token environment value, and no `setup_complete` marker, enters setup. An established configuration starts normally. Invalid JSON, unreadable files, and broken credential-file references produce an error requiring correction.

Do not delete an established configuration to change settings or reset an account. Use the administration page or the recovery steps below. To try a separate installation, pass a different config path **and select a different data directory and free ports**:

```sh
xmake run postplus --config "config/trial.json" --setup-port 8082
```

### A remote Linux or Windows server

`127.0.0.1` always means the computer where the browser runs. To open setup directly on a remote server, choose `0.0.0.0` at first launch and enter the server's reachable hostname or IP. You can also select it explicitly:

```sh
./postplus --setup-bind 0.0.0.0 --setup-host SERVER-IP
```

Replace `SERVER-IP` with the address used by your browser, then open the printed URL and enter the one-time password. No existing certificate is required. Remote HTTP setup sends credentials without encryption; use a trusted network or configure setup HTTPS below when encryption is needed.

For access through SSH, keep the loopback listener and forward its port from your own computer:

```sh
ssh -N -L 8081:127.0.0.1:8081 server-user@server-address
```

Keep the SSH session open, then visit `http://127.0.0.1:8081/` locally. Use the setup password from the **server's PostPlus terminal**. If you chose another setup port, use that port on both sides of the forwarding command. The setup Host/Origin checks expect the selected setup port, so keep the local and remote port numbers the same.

No public firewall rule is needed for setup over this tunnel. The tunnel can also reach the normal admin interface when `admin_bind` remains `127.0.0.1`. After enabling TLS, the normal interface uses HTTPS and the browser must access a hostname covered by the certificate; the tunnel does not remove certificate verification.

### Direct HTTPS setup on a remote server

If you already have a certificate for a reachable setup hostname, you can enable HTTPS for the temporary wizard:

```sh
xmake run postplus --setup-bind 0.0.0.0 --setup-host setup.example.com --setup-port 8081 --setup-tls-certificate /srv/tls/setup/fullchain.pem --setup-tls-private-key /srv/tls/setup/privkey.pem
```

Use the HTTPS URL printed by PostPlus and the separate one-time password. Replace the hostname and paths with your own; the browser must trust the certificate and its hostname. A wildcard bind requires `--setup-host`; both TLS files must be supplied together when enabling HTTPS. These flags control only the temporary wizard; configure the permanent administration and Webmail listeners in the form. If you do not yet have a certificate, use HTTP setup on a trusted network or an SSH tunnel, then request a certificate as described below.

## 3. Complete the first-run form

For a first trial on one computer, use the values below. Expand advanced sections only when you need them.

| Form area | Suggested local trial | What it means |
| --- | --- | --- |
| Server identity | Domain `localhost` | Addresses will look like `alice@localhost`; this domain cannot receive internet mail. |
| First administrator | `admin@localhost` and a new password | Use a password of at least 8 characters. Save it in a password manager. |
| Data directory | Keep the suggested directory | Stores accounts, messages, queues, and default logs. Choose a persistent, writable disk location. |
| Connections and security | Loopback addresses; local development enabled | Allows a local trial without certificates. Clients on other computers cannot use this mode for plaintext login. |
| Administration port | `8081` | Server management page; separate from Webmail. |
| Webmail port | `80` | Reading and composing mail in a browser. |
| SMTP / POP3 / IMAP | `25` / `110` / `143` | SMTP uses the Internet receiving port; Unix requires permission to bind TCP 25. |
| Internal ports | Keep the suggested values | Private communication between service processes; each must be distinct. |
| Outgoing delivery | Choose disabled for the local trial | Local recipients work. A real-domain deployment can select built-in direct delivery or an SMTP relay. |
| ClamAV | Leave host empty for this trial | Built-in filtering remains active; full malware scanning needs a separate ClamAV service. |

Save the form. PostPlus validates the values, creates the administrator and private configuration files, closes setup, and starts the service group. Use the success page's links or the addresses printed by the launcher.

On Linux, the standard ports require permission to bind ports below 1024. For an initial terminal setup, grant that capability to the launcher and public listeners using the paths in your extracted release:

```sh
sudo setcap cap_net_bind_service=+ep ./postplus ./postplus-smtp ./postplus-pop3 ./postplus-imap ./postplus-web
```

Alternatively, temporarily use high ports for **all** public listeners (for example SMTP 2525, POP3 1110, IMAP 1143 and Web 8080). Stop with **Ctrl+C** after setup and [install the systemd service](systemd.md), which grants `CAP_NET_BIND_SERVICE`. Then use **Apply standard ports** in administration and save. Existing managed systemd installations already have the capability. Terminal file capabilities must be re-applied after replacing a binary; prefer systemd for automatic upgrades.

The generated internal service token lives in a private file referenced by `service_token_file`. You do not need to copy it into the browser or set `POSTPLUS_SERVICE_TOKEN` for a wizard-created installation. Your administrator password is stored as a salted password hash in the authentication database, not in the configuration.

## 4. Create users and exchange a message

1. Open **Administration** at `http://127.0.0.1:8081/` for the local trial.
2. Sign in with the permanent administrator address and password created in setup.
3. Open **User accounts**. Enter `alice` and `bob` to create `alice@localhost` and `bob@localhost`, each with a password that meets the displayed rules (at least 8 characters by default). Leave administrator privileges disabled for regular users.
4. Open **Webmail** at `http://127.0.0.1:80/`. Sign in as Alice.
5. Compose a message to `bob@localhost`, add a subject and text, and send it.
6. Sign out, sign in as Bob, and refresh the inbox. Delivery is queued, so a message can take a short time to appear.

Webmail has no registration page. Every account must be created by an administrator. Setup, account creation, administration login, and Webmail login show the fixed `@domain`, so enter only the name before it. Pasting a complete address on the same domain also works. Mail clients and API calls use the full email address. The administrator can also use Webmail by signing in separately.

Use **Delivery queue** to inspect delayed or quarantined mail and **Service logs** to see errors. Sent copies appear when Webmail submits mail successfully; final delivery can happen later.

### Customize the interface

Open **Settings** near your account at the bottom of the navigation panel. Language and appearance controls are also available before signing in and during first-run setup.

- Choose **English** or **简体中文**. English is the default.
- Choose a light or dark theme, or follow the system appearance. System mode is the default and responds when your device changes theme.
- Adjust display density and, in Webmail, the reading text size. These preferences apply immediately and are remembered in the current browser for each portal. They do not change mail or server configuration.

On a phone, use the navigation button to open folders or administration pages. Selecting a destination closes the navigation panel. Open a message to read it, then use the back button to return to the list. Wide administration tables scroll within their section.

In administration, open **User accounts → Account password policy**. Set the minimum length and select any required uppercase letters, lowercase letters, digits, or symbols, then save. The default minimum is 8 characters, with no mandatory character categories. The policy is stored on the server and applies to future account creation and password resets, including CLI operations; existing passwords and sessions remain valid. **Server settings** is the separate page for ports, TLS, delivery and other operating settings.

### Organize mail and resume drafts

| Folder | How to use it |
| --- | --- |
| Inbox | Mail delivered to your account. |
| Sent | Copies saved when you successfully submit mail from Webmail. Check the delivery queue if delivery is delayed. |
| Drafts | Click **Save draft** while composing. Open a saved draft, choose **Edit draft**, and save again or send it. |
| Trash | **Move to Trash** keeps a message recoverable. Use **Move to…** to restore it. **Delete permanently** in Trash removes it after confirmation. |
| Junk | Keep unwanted mail separate. Moving mail here does not train the spam filter. |
| Archive | Keep mail without leaving it in Inbox. |

Use **Move to…** in the message reader to choose a destination. Drafts share your mailbox quota, and sending a saved draft turns it into a Sent copy. **Discard changes** closes the editor without saving unsaved edits; it does not delete an existing saved draft. To remove a saved draft, move it to Trash from its folder.

### Inspect an account and set its storage quota

In **Administration → User accounts**, choose **Inspect mail** beside an account. Select received mail, sent mail, another folder, or **All folders**, then open a message. This view is read-only and does not mark the account’s mail as read. The administrator’s inspection is recorded in service logs.

Choose **Storage quota** beside the account to see its current usage. Keep **Use the server’s default storage quota** selected to inherit the global limit, or clear it and enter an individual limit. Choose a size unit such as MiB or GiB; 1 GiB is 1,073,741,824 bytes. Save to apply the override immediately, without restarting other services. All folders count toward the account’s usage. Lowering a limit does not delete existing mail; new mail and drafts need available capacity.
### Connect a mail client

For the local trial, use this manual account configuration:

| Setting | Value |
| --- | --- |
| Username | Full address, such as `alice@localhost` |
| Password | That account's permanent password |
| Incoming server | `127.0.0.1` |
| Incoming protocol | IMAP on `143`, or POP3 on `110` |
| Outgoing server | `127.0.0.1`, SMTP on `25` |
| Local trial encryption | None, only with explicit loopback development mode |
| TLS installation encryption | STARTTLS for SMTP and IMAP; STLS/STARTTLS for POP3 |
| SMTP authentication | Enabled, with the full address and password |

For deployment, use the server hostname and the **Mail clients** section in setup or administration. With a certificate configured, IMAP 993 and POP3 995 use SSL/TLS; SMTP 587 uses STARTTLS and SMTP 465 uses SSL/TLS. Both SMTP submission listeners require authentication and encryption. See [client and DNS settings](mail-clients.md) for discovery records and compatibility details.

## 5. Change settings in administration

Open **Server settings** for domain, network, TLS, outgoing mail, filtering, limits, sessions, and logs. The form explains fields and checks types, ranges, and conflicting ports before saving. Size fields have unit selectors; for example, enter 10 MiB instead of 10485760 bytes. Changing only the displayed unit preserves the exact byte count, and the config file always stores integer bytes.

Saving validates and backs up the configuration, then **automatically restarts only affected services** when PostPlus is running through its native supervisor. The page shows the affected services, progress, and updated admin/Webmail addresses. Services that do not need the changed settings continue running. Your administration session stays available unless the administration service itself restarts; in that case, open the updated administration address and sign in again. A disconnected page alone does not confirm that restarting succeeded.

Use **Server maintenance → Restart all services** when you need a full restart with the saved configuration. Unsaved form edits are not included. With the supplied systemd installation, PostPlus automatically comes back after this action. **Save and shut down** is a separate operation: it saves without starting an automatic restart and leaves the installation stopped.

If a changed address, port, or certificate prevents restarting, the native supervisor attempts to restore the previous affected services. The page reports restoration when confirmed; the new saved settings remain pending and must be corrected before retrying. If recovery also fails, check the service logs and start PostPlus after correcting the configuration or restoring its backup. A full systemd relaunch cannot restore old processes automatically.

The data directory is read-only after installation. It contains the installation's accounts and mail; moving it requires stopping the group, copying the complete data directory, and updating the configuration deliberately. Changing the domain does not rename existing account addresses or migrate mailboxes. Choose the intended domain before creating real users.

For settings stored only in the config file, and examples of manual editing, see the [configuration reference](configuration.md). If services were started individually instead of through `postplus`, restart them yourself after a configuration save.

## 6. Move from a local trial to a real domain

Suppose you control `example.com` and want addresses such as `alice@example.com`, with a mail server named `mail.example.com`.

1. **Choose the mailbox domain.** Select `example.com` during setup. This is the part after `@`; it need not equal the machine's hostname. Setup configures one domain; add further domains through **Administration → Domains**. The first domain is fixed after installation.
2. **Prepare DNS.** Point an A record for `mail.example.com` at the server's public IPv4 address. Add AAAA only if IPv6 actually reaches the configured listener. For direct inbound internet mail, point `example.com`'s MX record at `mail.example.com`. MX records name a host, not an IP address, URL, or custom port.
3. **Arrange inbound SMTP.** Other mail servers deliver to TCP port 25. The default SMTP port is `25`. If you choose a custom port such as `2525`, configure controlled forwarding from public TCP 25. Confirm the hosting provider and firewall permit inbound SMTP. A port value in the page does not create firewall/NAT rules or give the process permission to bind privileged ports.
4. **Obtain a certificate.** Request one through PostPlus’s Let’s Encrypt panel (below), or use another provider. The certificate must cover `mail.example.com`; its PEM chain and matching unencrypted private key must be readable by the service account.
5. **Configure TLS and listening.** Save certificate paths under **Domains → Manage domain → TLS certificates**. In Server settings, disable local plaintext authentication and choose a reachable bind address. `0.0.0.0` means all IPv4 interfaces; `127.0.0.1` means local access only. Keep the administration bind on loopback if you manage it through a tunnel. All configured ports must differ, including admin and Webmail.
6. **Access the correct name.** To use `https://mail.example.com/` for `@example.com` accounts, set that hostname in the domain's **Webmail address** tab and install a certificate covering it. Use standard HTTPS port 443, or append your custom listener port. **Domains → Login addresses** controls administration and optional shared Webmail entry points. PostPlus selects per-host certificates with SNI and retains a default pair for clients without SNI. Accessing by an IP or another name can cause a certificate-name error.
7. **Configure outgoing delivery.** Choose built-in direct delivery or an SMTP relay as described below, then create addresses in the real domain and test a local message before testing an external recipient.

You can run the administration port on a separate network address without making it publicly accessible. DNS, TLS, firewall rules, and relay permission must all agree with the names and ports you actually use. The setup form validates local settings but does not prove external reachability or email deliverability.

### Fill in DNS records

First-run setup guides you through the domain and hostname, receiving mail, sending authentication, and the certificate. For mailbox domain `example.com`, it suggests `mail.example.com` as the mail hostname and preserves manual hostname edits. Add the `mail` A/AAAA records and the root MX; **you do not need to replace your existing website's root A record**. A local `localhost` trial can skip public DNS.

**Configure receiving first.** Enter the server's public addresses to generate records you can copy into the provider hosting your authoritative DNS:

| Type | Name in the `example.com` DNS zone | Value | Purpose |
| --- | --- | --- | --- |
| A | `mail` | The public IPv4 entered in setup | Let mail clients and other servers find the mail host. |
| AAAA (optional) | `mail` | Your working public IPv6 address | Publish only when IPv6 reaches the mail services. |
| MX | `@` | `mail.example.com`, priority `10` | Receive mail for `@example.com`; public TCP 25 must reach the configured SMTP port. |

`@` means the zone's root. Most DNS panels append `example.com`, so enter `mail`; panels requiring a complete name use `mail.example.com`. The wizard shows both forms. If the mail hostname belongs to another domain, create A/AAAA in that domain's DNS zone; the mailbox MX still belongs to `example.com`. Select DNS-only for the mail hostname when your provider offers an HTTP proxy.

**Send directly from your server.** Choose **Built-in direct delivery** in step 3. PostPlus queries recipient MX records and sends on TCP 25 without a relay. Enter the public IP addresses actually used for outbound SMTP, then generate/load DKIM. The server creates a private RSA key and shows the real public TXT record to publish. Retrying or restarting setup reuses that key.

**Publish sending authentication.** Direct mode generates SPF from the public IPs you enter and DKIM from the server's generated public key. For an SMTP relay, enter its actual SPF policy and public DKIM TXT/CNAME record. Disabled mode lets you receive Internet mail and exchange messages between local accounts while preparing outbound delivery later.

- SPF: publish the generated direct-sending policy or the relay's complete `v=spf1 …` policy. Merge with an existing policy so there is only one SPF TXT at that name. If the relay requires a separate return-path domain, follow its instructions.
- DKIM: publish the generated public TXT at `<selector>._domainkey.example.com`. For a relay, enable signing and use its actual public TXT or CNAME. Never publish a private key.
- DMARC: setup suggests TXT `v=DMARC1; p=none` at `_dmarc`. Confirm SPF or DKIM aligns with the sender domain before choosing `quarantine` or `reject`. Keep an existing suitable policy rather than adding a duplicate.

Direct mode signs outgoing mail with the generated DKIM key; publish its TXT at `postplus._domainkey.example.com` or your chosen selector. Allow **outbound TCP 25** and ask the hosting provider to set the outbound IP's **PTR** to `mail.example.com`; that hostname's A/AAAA must resolve back to the IP. After deployment, send a test message and inspect authentication results. DNS matching does not prove port reachability, IP reputation or inbox placement.

**After publishing, click “Check public DNS”.** The server queries A, AAAA, MX, SPF, DKIM and DMARC through a fixed public resolver. Each record shows matched, missing, mismatched, unconfigured or lookup failed, with observed values, the check time and resolver. Changing inputs invalidates old results. Saving persists delivery mode, SMTP hostname, DKIM selector and private-key path. DNS records are published separately in your provider's panel.

The check requires outbound UDP port 53 to the public resolver. A lookup failure leaves the result unknown; fix connectivity and retry, or continue using your provider's panel and external checks. A match only reflects what that resolver currently sees. It does not prove TCP 25 reachability, delivery, relay signing or certificate issuance.

**Prepare the certificate last.** For an existing certificate, enter server-side PEM paths and confirm that it covers the mail hostname. Only the built-in Let's Encrypt **HTTP-01** flow below requires public TCP 80; other issuance methods follow their provider's requirements. MX, SPF, DKIM and DMARC do not affect loading CA terms. The built-in flow does not request a DNS-01 `_acme-challenge` TXT record.

### Request a Let’s Encrypt certificate

The certificate panel is available in **Domains → Manage domain → TLS certificates** and in first-run setup after choosing TLS mode. Domain management also contains the DNS guide and checks for mail, Webmail, administration and shared login hostnames. Certificate requests use HTTP-01 domain validation:

1. Point the certificate hostname’s public A record at this server. If you publish AAAA, make IPv6 work too. Use the hostname clients will connect to, such as `mail.example.com`.
2. Make public TCP port **80** reach PostPlus. Stop any conflicting HTTP listener or configure forwarding to the challenge listener. PostPlus must have OS permission to bind its challenge port. The web administration port (normally 8081) is separate from port 80.
3. Select the certificate hostname, then expand **Get a certificate from Let’s Encrypt**. Domain management locks the request to that selected hostname; setup lets you enter it. Enter a contact email and select **Staging · test certificate** first.
4. Click **Load certificate authority terms**, read the linked terms, and check the agreement box if you accept them. Click **Request certificate**. Follow the status; you can cancel an in-progress request.
5. After the staging request succeeds, select **Production · trusted certificate**, load and accept its terms, and request again. Staging certificates are not trusted by normal browsers or mail clients.
6. When the production certificate is issued, click **Use these certificate paths**. This fills the certificate and private-key fields. Save the hostname certificate. Review the listening addresses and disable plaintext authentication for network access in Server settings.
7. For an existing supervised installation, saving automatically restarts affected services to load the certificate. Follow the restart panel and sign in again if administration restarts. Standalone services require a manual restart. The first-run wizard starts services when its configuration is saved.

Certificates and account credentials are saved privately on the server. PostPlus does not configure DNS or your firewall, and successful local setup is not proof of public reachability. Automatic renewal is not implemented: track certificate expiry and request a replacement before it expires, then save to apply the new paths automatically. Independently launched services still require a manual restart. You can still use a certificate obtained through another provider by entering its PEM paths directly.

### Built-in direct delivery or an SMTP relay

To deploy without another mail server, select direct delivery, set a public mail hostname, prepare and publish the DKIM key, and save. Existing installations can prepare a key in **Server settings → Outgoing mail**. Temporary failures retry with exponential backoff for five days by default; permanent failures and expired jobs remain visible in the administration queue. Automatic delivery-failure emails are not generated.

For an SMTP relay, select relay mode and configure a provider or another server that accepts and forwards mail for your domain. A self-hosted relay on loopback can use `smarthost_tls: "none"` without authentication; remote relays require TLS. Never point a relay at PostPlus's own SMTP listener.

In **Server settings**, configure:

- Relay host and port supplied by your provider, commonly port `587` with `starttls` or port `465` with `implicit` TLS.
- Relay username, if required.
- The relay password, entered into the password field. It is written to a private secret file and is not displayed again; leaving this field blank in later edits keeps the saved password.

Alternatively, set the password through an environment variable, normally `POSTPLUS_SMARTHOST_PASSWORD`, and enter that variable's **name** in the relay environment field. A nonempty environment value takes precedence over the saved password. Set it in the environment used to launch PostPlus or in your service manager's protected configuration, then restart the launcher. Avoid putting a real password in a shell command saved to history. `service_token_file` is a different credential and cannot authenticate with the SMTP provider.

Outbound TLS verifies certificate trust and hostname. Direct sending uses STARTTLS when offered and defers after TLS failures; required TLS can be selected. Relay mode follows the provider's domain-verification and SPF/DKIM instructions. PostPlus does not verify SPF/DKIM/DMARC on incoming mail.

### Spam rules and ClamAV

Set blocked terms, the spam threshold and sender/domain allow or block rules in administration. Ordinary inbound spam goes to Junk with its score and reasons. Matching handles MIME encodings, HTML text entities, inline markup and common invisible separators. A harmless [GTUBE test message](configuration.md#mail-filtering) verifies inbound Junk routing. Built-in matching is a baseline rule filter, not a trained spam classifier; optional local Rspamd adds its configured checks. Malware, malformed MIME and explicit blocked-term matches go to quarantine; changing rules does not automatically release existing quarantined mail.

For full antivirus scanning, separately install ClamAV, maintain its signatures, and make its `clamd` INSTREAM service reachable from PostPlus. Enter `clamav_host`, `clamav_port` (usually `3310`), and a suitable timeout. The built-in EICAR check is only a test-signature detector. Scanner outages defer delivery for retry; they are not treated as a successful clean scan. Check the delivery queue and filter logs after enabling scanning.

## 7. Stop, back up, and recover

On Linux, a completed setup can run as a systemd service. Stop the terminal
instance, then run `sudo bash scripts/install-systemd.sh` from the extracted
installation. See the [service guide](systemd.md) for prerequisites, options,
logs, and `systemctl` commands.

Press **Ctrl+C** in the launcher terminal and wait until the group exits. For a consistent offline backup, copy the entire data directory, configuration, referenced service/relay secrets, DKIM private key, and TLS credentials to protected storage. Do not copy only live `.sqlite3` files: recent changes can be in SQLite WAL files. See [Backup and recovery](architecture.md#backup-and-recovery).

After restoring or making a manual change, run PostPlus with the same explicit `--config` path and inspect the terminal. Keep the old config or the save-generated backup until the new configuration has started successfully. To recover from an unreachable admin listener, stop PostPlus and correct `admin_bind`, `ports.admin`, or TLS paths in the file, then restart.

An administrator password can be reset from a local terminal while the services are running:

```sh
xmake run postplus-ctl password admin@example.com --config config/postplus.json
```

The command prompts for the new password; do not put it in command-line arguments. The CLI requires access to the installation's service credential. Existing sessions in both browser services become invalid on their next authenticated request.

### Reset a disposable installation while keeping its configuration

This operation permanently removes **all user accounts, mail in every folder, stored drafts, and delivery queues** from the selected installation. It is for starting over, not for routine password recovery. Make an offline backup first if any data matters.

Stop PostPlus, then preview the exact files to be removed:

```sh
xmake run postplus-clean-data --config config/postplus.json --dry-run
```

After reviewing that the printed data directory is the intended installation, run the same command without `--dry-run`:

```sh
xmake run postplus-clean-data --config config/postplus.json
xmake run postplus --config config/postplus.json
```

The utility removes only the known authentication/mail SQLite database files and their `-wal`, `-shm`, and `-journal` companions. Configuration, service secrets, logs, certificates, and unrelated files are retained. It marks the configuration with `setup_required: true`, so the next launch prints a new one-time setup password and lets you recreate the administrator while keeping server settings. It refuses to run while the data directory is in use.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| No first-run prompt | Check the configuration path printed/used by the launcher. An initialized installation starts normally; use its admin address. Use a separate config and data directory for a fresh trial. |
| Setup password rejected | Use the password from the currently running launcher. Restarting setup generates a new one. Paste it without added spaces. |
| Setup works on the server but not another PC | Choose `0.0.0.0` at first launch or pass `--setup-bind 0.0.0.0 --setup-host SERVER-IP`. Check that the setup port is reachable; `127.0.0.1` in your browser refers to your PC. SSH forwarding also works. |
| Port unavailable / address already in use | Another program or PostPlus instance may be using the port. Stop that instance or choose a free port. Admin and Webmail must have distinct ports. |
| `setup web asset is missing` | Build again, keep the bundled `web` folder beside the executables, or pass `--web-root` pointing at this repository's `web` folder. |
| Service token missing or invalid | A configured token-file path must be readable and contain the installation's token. A nonempty token environment variable overrides the file. Restore the correct secret; do not replace an established data directory to resolve this. |
| Login requires TLS | Enable TLS, or use the explicit development option from loopback for a local trial. Public plaintext login is not supported. |
| TLS files rejected | Use a readable PEM certificate chain and matching unencrypted PEM key on the server. Check paths and service-account permissions. |
| Browser certificate error | Use the hostname covered by the certificate; check expiration and chain trust. The mail domain and TLS hostname can differ. |
| Saved settings have not taken effect | Check the restart progress and logs. Supervised saves restart affected services automatically; independently launched services require a manual restart. Use the updated URL if the admin address changed. |
| Page disconnected after restarting | An administration-service restart ends its browser session. Open the updated address and sign in again to check the result; inspect service logs if it does not return. Other service restarts preserve the administration session. |
| No mail arrives | Confirm recipient exists, inspect Delivery queue, then check storage/delivery/filter/transfer logs. External sending requires enabled direct or relay delivery. |
| Mail waits after enabling ClamAV | Confirm `clamd` is running and reachable and signatures are loaded. Scanner failures defer delivery. |
| Internet sender cannot reach the mailbox | Check MX/A/AAAA records, inbound TCP 25, firewall/NAT/provider restrictions, and the configured local recipient. |
| Mail client has missing folders/features | Compare its needs with the [protocol support matrix](protocols.md). Full IMAP compatibility is still in development. |

### Sending works, but mail from Outlook or another provider never arrives

Internet mail servers use the MX hostname on **TCP port 25**. They do not use
the SMTP port entered in a mail client, and MX records cannot select port 2525.
If PostPlus responds on 2525 while port 25 times out, incoming mail cannot reach
it even when MX, SPF, DKIM and DMARC records match.

In **Server settings**, set the SMTP port to `25` and save; PostPlus automatically restarts the affected services
to apply it. On Linux, the supplied [systemd installer](systemd.md) grants the
service account permission to bind privileged ports. Permit inbound TCP 25 in
the VPS provider's firewall/security group and the host firewall; for example,
when UFW is in use, `sudo ufw allow 25/tcp`. An existing controlled forwarding
arrangement from public TCP 25 to PostPlus's 2525 listener also works. Check
the local listener and test from another network:

```sh
sudo ss -ltnp '( sport = :25 or sport = :2525 )'
nc -vz -w 5 mail.example.com 25
```

The listener must use a reachable address such as `0.0.0.0`, with TLS configured
for public deployment. Preserve the existing configuration, DKIM key and
accounts when adjusting these fields.

For `alice@example.com`, set the mailbox domain to `example.com` and create
that exact local account. `mail.example.com` is the server/MX hostname; it does
not make `alice@mail.example.com` a local mailbox. Outside senders can deliver
to existing local accounts without logging in, including when outgoing
delivery is disabled. After SMTP accepts the message, inspect **Delivery
queue** and the `delivery`, `storage` and `filter` logs if it is absent from
the inbox; a queued or quarantined message may still need attention.

For operational details, see [architecture](architecture.md), [configuration](configuration.md), and the [HTTP API](api.md).
