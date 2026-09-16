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

On an unconfigured installation, the terminal prints a **setup required** notice, a browser address, and a **one-time setup password**. The normal address is:

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

`127.0.0.1` always means the computer where the browser runs. Setup deliberately listens only on the server's loopback address. If the server has no browser, use SSH port forwarding from your own computer:

```sh
ssh -N -L 8081:127.0.0.1:8081 server-user@server-address
```

Keep the SSH session open, then visit `http://127.0.0.1:8081/` locally. Use the setup password from the **server's PostPlus terminal**. If you chose another setup port, use that port on both sides of the forwarding command. The setup Host/Origin checks expect the selected setup port, so keep the local and remote port numbers the same.

No public firewall rule is needed for setup over this tunnel. The tunnel can also reach the normal admin interface when `admin_bind` remains `127.0.0.1`. After enabling TLS, the normal interface uses HTTPS and the browser must access a hostname covered by the certificate; the tunnel does not remove certificate verification.

## 3. Complete the first-run form

For a first trial on one computer, use the values below. Expand advanced sections only when you need them.

| Form area | Suggested local trial | What it means |
| --- | --- | --- |
| Server identity | Domain `localhost` | Addresses will look like `alice@localhost`; this domain cannot receive internet mail. |
| First administrator | `admin@localhost` and a new password | Use a password of at least 12 characters. Save it in a password manager. |
| Data directory | Keep the suggested directory | Stores accounts, messages, queues, and default logs. Choose a persistent, writable disk location. |
| Connections and security | Loopback addresses; local development enabled | Allows a local trial without certificates. Clients on other computers cannot use this mode for plaintext login. |
| Administration port | `8081` | Server management page; separate from Webmail. |
| Webmail port | `8080` | Reading and composing mail in a browser. |
| SMTP / POP3 / IMAP | `2525` / `1110` / `1143` | Non-privileged development ports for mail clients. |
| Internal ports | Keep the suggested values | Private communication between service processes; each must be distinct. |
| Outgoing relay | Leave host empty | Local recipients work. Sending to an external domain requires a relay. |
| ClamAV | Leave host empty for this trial | Built-in filtering remains active; full malware scanning needs a separate ClamAV service. |

Save the form. PostPlus validates the values, creates the administrator and private configuration files, closes setup, and starts the service group. Use the success page's links or the addresses printed by the launcher.

The generated internal service token lives in a private file referenced by `service_token_file`. You do not need to copy it into the browser or set `POSTPLUS_SERVICE_TOKEN` for a wizard-created installation. Your administrator password is stored as a salted password hash in the authentication database, not in the configuration.

## 4. Create users and exchange a message

1. Open **Administration** at `http://127.0.0.1:8081/` for the local trial.
2. Sign in with the permanent administrator address and password created in setup.
3. Open **User accounts**. Create `alice@localhost` and `bob@localhost`, each with a password of at least 12 characters. Leave administrator privileges disabled for regular users.
4. Open **Webmail** at `http://127.0.0.1:8080/`. Sign in as Alice.
5. Compose a message to `bob@localhost`, add a subject and text, and send it.
6. Sign out, sign in as Bob, and refresh the inbox. Delivery is queued, so a message can take a short time to appear.

Webmail has no registration page. Every account must be created by an administrator. Usernames are full email addresses, not just the part before `@`. The administrator can also use Webmail by signing in separately.

Use **Delivery queue** to inspect delayed or quarantined mail and **Service logs** to see errors. No Sent folder is implemented yet; the sending account should not expect an automatic saved copy.

### Connect a mail client

For the local trial, use this manual account configuration:

| Setting | Value |
| --- | --- |
| Username | Full address, such as `alice@localhost` |
| Password | That account's permanent password |
| Incoming server | `127.0.0.1` |
| Incoming protocol | IMAP on `1143`, or POP3 on `1110` |
| Outgoing server | `127.0.0.1`, SMTP on `2525` |
| Local trial encryption | None, only with explicit loopback development mode |
| TLS installation encryption | STARTTLS for SMTP and IMAP; STLS/STARTTLS for POP3 |
| SMTP authentication | Enabled, with the full address and password |

Use the real server hostname and configured ports after deployment. Implicit TLS ports such as SMTP 465, IMAP 993, and POP3 995 are not implemented for incoming client connections. Merely changing the port number does not change this. The [protocol matrix](protocols.md) lists the supported IMAP commands; clients requiring folders, IDLE, or other unsupported extensions may need additional development.

## 5. Change settings in administration

Open **Server settings** for domain, network, TLS, outgoing mail, filtering, limits, sessions, and logs. The form explains fields and checks types, ranges, and conflicting ports before saving.

Saving writes and backs up the configuration. **It does not restart the server.** The existing service group and browser sessions continue with the current settings until you choose to apply the change:

1. Note the new admin and Webmail URLs displayed by the settings page.
2. Press **Ctrl+C** in the launcher terminal and wait for all services to stop.
3. Run the same command again, including the same `--config` option if you used one.
4. Wait for startup, open the resulting admin URL, and sign in again. Sessions from before shutdown are no longer valid.

If a changed address, port, or certificate prevents startup, correct the file or restore its save-generated backup and run again. The launcher reports startup errors; it does not automatically roll back the saved configuration.

The data directory is read-only after installation. It contains the installation's accounts and mail; moving it requires stopping the group, copying the complete data directory, and updating the configuration deliberately. Changing the domain does not rename existing account addresses or migrate mailboxes. Choose the intended domain before creating real users.

For settings stored only in the config file, and examples of manual editing, see the [configuration reference](configuration.md). If services were started individually instead of through `postplus`, restart them yourself after a configuration save.

## 6. Move from a local trial to a real domain

Suppose you control `example.com` and want addresses such as `alice@example.com`, with a mail server named `mail.example.com`.

1. **Choose the mailbox domain.** Set PostPlus's domain to `example.com`. This is the part after `@`; it need not equal the machine's hostname. PostPlus currently supports one mailbox domain.
2. **Prepare DNS.** Point an A record for `mail.example.com` at the server's public IPv4 address. Add AAAA only if IPv6 actually reaches the configured listener. For direct inbound internet mail, point `example.com`'s MX record at `mail.example.com`. MX records name a host, not an IP address, URL, or custom port.
3. **Arrange inbound SMTP.** Other mail servers deliver to TCP port 25. The local default `2525` is for testing: configure an appropriate port 25 listener or a controlled forwarding arrangement. Confirm the hosting provider and firewall permit inbound SMTP. A port value in the page does not create firewall/NAT rules or give the process permission to bind privileged ports.
4. **Obtain a certificate.** Use your certificate provider or ACME client to obtain a PEM certificate chain and its matching, unencrypted PEM private key for `mail.example.com`. Put both on the server where the service account can read them. Protect the private key. PostPlus does not request or renew certificates.
5. **Configure TLS and listening.** In Server settings, enter those paths, disable local plaintext authentication, and choose a reachable bind address. `0.0.0.0` means all IPv4 interfaces; `127.0.0.1` means local access only. Keep the administration bind on loopback if you manage it through a tunnel. All configured ports must differ, including admin and Webmail.
6. **Access the correct name.** Use `https://mail.example.com:8080/` for Webmail if that is the configured port and certificate name. Accessing by an IP or another domain can cause a certificate-name error. PostPlus uses one configured certificate/key pair for its TLS listeners.
7. **Configure an outbound relay.** Follow the next section, then create addresses in the real domain and test a local message before testing an external recipient.

You can run the administration port on a separate network address without making it publicly accessible. DNS, TLS, firewall rules, and relay permission must all agree with the names and ports you actually use. The setup form validates local settings but does not prove external reachability or email deliverability.

### Outbound SMTP relay

PostPlus sends external mail through a smarthost: an SMTP provider or another server that accepts and forwards mail for your domain. It does not perform direct destination-MX delivery.

In **Server settings**, configure:

- Relay host and port supplied by your provider, commonly port `587` with `starttls` or port `465` with `implicit` TLS.
- Relay username, if required.
- The relay password, entered into the password field. It is written to a private secret file and is not displayed again; leaving this field blank in later edits keeps the saved password.

Alternatively, set the password through an environment variable, normally `POSTPLUS_SMARTHOST_PASSWORD`, and enter that variable's **name** in the relay environment field. A nonempty environment value takes precedence over the saved password. Set it in the environment used to launch PostPlus or in your service manager's protected configuration, then restart the launcher. Avoid putting a real password in a shell command saved to history. `service_token_file` is a different credential and cannot authenticate with the SMTP provider.

Outbound TLS verifies the relay certificate and hostname. If the platform needs an explicit trust store, configure OpenSSL's `SSL_CERT_FILE` or `SSL_CERT_DIR` before starting PostPlus. Follow the provider's domain-verification, sending-policy, and SPF/DKIM instructions. PostPlus itself does not implement SPF, DKIM signing, or DMARC processing, so use capabilities supplied by the relay where appropriate.

### Spam rules and ClamAV

Set blocked terms and the spam threshold in administration. Built-in matching is a baseline rule filter, not a trained spam classifier. Rejections go to quarantine; changing rules does not automatically release existing quarantined mail.

For full antivirus scanning, separately install ClamAV, maintain its signatures, and make its `clamd` INSTREAM service reachable from PostPlus. Enter `clamav_host`, `clamav_port` (usually `3310`), and a suitable timeout. The built-in EICAR check is only a test-signature detector. Scanner outages defer delivery for retry; they are not treated as a successful clean scan. Check the delivery queue and filter logs after enabling scanning.

## 7. Stop, back up, and recover

Press **Ctrl+C** in the launcher terminal and wait until the group exits. For a consistent offline backup, copy the entire data directory, configuration, referenced service-token file, and TLS credentials to protected storage. Do not copy only live `.sqlite3` files: recent changes can be in SQLite WAL files. See [Backup and recovery](architecture.md#backup-and-recovery).

After restoring or making a manual change, run PostPlus with the same explicit `--config` path and inspect the terminal. Keep the old config or the save-generated backup until the new configuration has started successfully. To recover from an unreachable admin listener, stop PostPlus and correct `admin_bind`, `ports.admin`, or TLS paths in the file, then restart.

An administrator password can be reset from a local terminal while the services are running:

```sh
xmake run postplus-ctl password admin@example.com --config config/postplus.json
```

The command prompts for the new password; do not put it in command-line arguments. The CLI requires access to the installation's service credential. Existing sessions in both browser services become invalid on their next authenticated request.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| No first-run prompt | Check the configuration path printed/used by the launcher. An initialized installation starts normally; use its admin address. Use a separate config and data directory for a fresh trial. |
| Setup password rejected | Use the password from the currently running launcher. Restarting setup generates a new one. Paste it without added spaces. |
| Setup works on the server but not another PC | Setup is loopback-only. Use the SSH forwarding instructions; `127.0.0.1` in your browser refers to your PC. |
| Port unavailable / address already in use | Another program or PostPlus instance may be using the port. Stop that instance or choose a free port. Admin and Webmail must have distinct ports. |
| `setup web asset is missing` | Build again, keep the bundled `web` folder beside the executables, or pass `--web-root` pointing at this repository's `web` folder. |
| Service token missing or invalid | A configured token-file path must be readable and contain the installation's token. A nonempty token environment variable overrides the file. Restore the correct secret; do not replace an established data directory to resolve this. |
| Login requires TLS | Enable TLS, or use the explicit development option from loopback for a local trial. Public plaintext login is not supported. |
| TLS files rejected | Use a readable PEM certificate chain and matching unencrypted PEM key on the server. Check paths and service-account permissions. |
| Browser certificate error | Use the hostname covered by the certificate; check expiration and chain trust. The mail domain and TLS hostname can differ. |
| Saved settings have not taken effect | Saving does not restart services. Stop the launcher with Ctrl+C, wait for shutdown, then run the same command. Use the new URL after startup. |
| Page disconnected after restarting | Browser sessions expire when services stop. Wait for startup, use the new admin address, and sign in again. Inspect the terminal if the service does not return. |
| No mail arrives | Confirm recipient exists, inspect Delivery queue, then check storage/delivery/filter/transfer logs. External mail also needs a relay. |
| Mail waits after enabling ClamAV | Confirm `clamd` is running and reachable and signatures are loaded. Scanner failures defer delivery. |
| Internet sender cannot reach the mailbox | Check MX/A/AAAA records, inbound TCP 25, firewall/NAT/provider restrictions, and the configured local recipient. |
| Mail client has missing folders/features | Compare its needs with the [protocol support matrix](protocols.md). Full IMAP compatibility is still in development. |

For operational details, see [architecture](architecture.md), [configuration](configuration.md), and the [HTTP API](api.md).
