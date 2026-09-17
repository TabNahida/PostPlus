# Backups and shutdown

## Create a backup

1. Sign in to **Administration** with an administrator account.
2. Open **Server settings**, then **Server maintenance**.
3. Save configuration changes you want included. Unsaved browser forms are not part of a backup.
4. Select **Create backup** and wait for **Download backup**.
5. Download the `.tar` archive and store it in a private, backed-up location.

The archive contains account password hashes, the live password policy, all mail folders, individual quotas, the delivery queue, saved server configuration, the service token, the configured relay password, and the configured TLS certificate/key pair. It includes `RESTORE.txt` with recovery instructions. Logs, binaries, older backups, and ACME account registration state are omitted. Certificates can be requested again through administration after a restore.

**Backups are not encrypted.** They contain private mail and credentials; anyone who can read an archive can access this information. Use an encrypted storage location and limit access to the server administrator.

PostPlus briefly locks database writes to establish one consistent snapshot of the accounts and mail databases, then copies both using SQLite's backup API. Normal mail activity resumes while the snapshot is written. The archive is streamed in fixed-size chunks, so downloading a large mailbox does not load it into server memory. Allow free disk space for the database snapshots and archive (approximately twice the combined database size), plus ongoing mail and SQLite WAL growth during the backup.

Only the latest backup in the current administration process is available. Download it before creating another backup or stopping the server. A new backup is refused while the previous one is being downloaded. Configuration saves and web shutdown are refused while a backup is running. Ctrl+C can cancel an unfinished backup during shutdown. After an abnormal process termination, a private `.backup-<random-id>` directory may remain inside `data_dir`; after stopping PostPlus, remove that specific incomplete directory if you no longer need it.

## Restore into a fresh installation

1. Stop PostPlus and retain the old installation until recovery has been verified.
2. Create an **empty private directory** owned by the operating-system user that will run PostPlus. On Linux/macOS, use `mkdir -m 700 /path/to/restored-postplus`. On Windows, restrict the directory's Security permissions to your server account and SYSTEM before extracting.
3. Extract the archive into that directory using `tar -xf /path/to/postplus-backup-....tar -C /path/to/restored-postplus`. Do not extract over a running installation or mix restored databases with old `-wal`/`-shm` files.
4. Copy all PostPlus executables and the `web` directory from the matching release into the restored directory. Keep `config` and `data` from the backup.
5. Check file permissions. Configuration, token, relay-secret, TLS-key and database files should be accessible only to the server account (mode `0600` on Linux/macOS).
6. Review `config/postplus.json`: listening addresses/ports, domain, relay and certificate validity. Backup paths are rewritten relative to the restored configuration: `../data`, `../web`, and files within `config`. Existing service-token and relay-password environment variables still take precedence over the restored secret files; remove unintended overrides.
7. From the restored directory, run `./postplus --config config/postplus.json` (Windows: `.\postplus.exe --config config/postplus.json`). Sign in with the existing administrator password. Verify user accounts, password policy, folders, quotas, and pending queue entries before restoring public traffic.

A restore returns the queue to its snapshot state. An external message successfully delivered **after** that snapshot may be sent again. This is inherent in restoring an outbound queue; inspect pending deliveries when recovering an older backup. Internal delivery identifiers remain in the same database snapshot and continue to prevent duplicate local delivery.

## Save and shut down from administration

Select **Server settings → Server maintenance → Save and shut down**. The page validates and saves the current Server settings form first. If validation or saving fails, the server keeps running. The account password policy has its own Save button; unsaved policy edits are not included.

After the shutdown request is accepted, the native `postplus` supervisor:

1. Closes SMTP, POP3, IMAP, Webmail, and administration listeners and waits for active work to finish.
2. Stops the delivery worker while keeping its dependencies available. Pending queue entries stay stored for the next start.
3. Stops filtering/transfer and closes the mail/account databases.

The terminal reports each service's progress, waits, and any forced termination. Each stage has a 35-second deadline. A service that exceeds it is forcibly stopped and the supervisor exits with an error rather than claiming a clean shutdown. Inspect logs before restarting after an error. An interrupted external SMTP delivery may be retried.

Web shutdown requires the native launcher. An administration service started separately cannot stop a server group and returns an error. The control request uses a private, randomly named, per-launch local directory; no extra public port is opened.

## Stop from the terminal

Press **Ctrl+C** once. The same staged shutdown runs and prints completion information even when the configured log level hides informational messages. Wait for **service group stopped; data saved** before closing the terminal. SIGTERM uses the same path on Linux/macOS.

Saved configuration still requires a **manual restart**. Start `postplus` again using your normal command to apply changes and resume mail service.
