# Run PostPlus as a Linux systemd service

[中文入门指南](getting-started.zh-CN.md) · [Getting started](getting-started.md)

The Linux release includes `scripts/install-systemd.sh`. After completing the
browser setup, use it to install `postplus.service`, start it at boot, and
restart the native supervisor if it fails.

## Install

Keep the complete extracted release in a permanent location. Finish browser
setup and stop the terminal instance with **Ctrl+C**, waiting for all services
to exit. From the installation directory:

```sh
bash scripts/install-systemd.sh --dry-run
sudo bash scripts/install-systemd.sh
```

The installer requires Bash, GNU coreutils, and a Linux host running systemd.
It uses the existing `config/postplus.json`; it does not copy the server or
change its configuration. The service uses the configuration file's owner
by default. That account must be able to read the configuration, service
credentials, and TLS files, execute all sibling service binaries, and write
the configuration directory, data directory, logs, and certificate directory.

For a different configuration or operating-system account:

```sh
sudo bash scripts/install-systemd.sh \
  --config /srv/postplus/config/postplus.json --user postplus
```

For a source build, provide the binary directory and repository working
directory explicitly:

```sh
sudo bash scripts/install-systemd.sh \
  --install-dir /srv/PostPlus/build/linux/x86_64/release \
  --working-dir /srv/PostPlus \
  --config /srv/PostPlus/config/postplus.json
```

`--dry-run` prints the proposed service without installing or starting it.
Running the installer again updates its managed unit. It refuses to overwrite
an unrelated `postplus.service`.

## Operate

```sh
systemctl status postplus.service
journalctl -u postplus.service -f
sudo systemctl restart postplus.service
sudo systemctl stop postplus.service
sudo systemctl disable --now postplus.service
```

After saving server settings, use `systemctl restart` to apply them. Stopping
the service signals the supervisor first and allows up to 130 seconds for its
ordered shutdown. Failed processes restart after five seconds. A successful
shutdown from administration leaves the service stopped until you start it
again with `sudo systemctl start postplus.service`.

The unit grants permission to bind privileged ports (for example SMTP 25 or
the ACME challenge port 80). All server processes continue to use the selected
service account.

If your saved configuration uses environment variables for credentials or
OpenSSL trust settings, add them to a systemd override: services do not inherit
your terminal environment. For example, create a private, root-owned file at
`/etc/postplus.env` with mode `0600`, then run
`sudo systemctl edit postplus.service` and add:

```ini
[Service]
EnvironmentFile=/etc/postplus.env
```

Restart the service after saving the override. Keep the installation at the
configured path; if you move the binaries, rerun the installer with the new
paths after stopping the service.

## 中文说明

完成网页 setup 后，按 Ctrl+C 停止终端中的实例，在解压后的安装目录运行
`sudo bash scripts/install-systemd.sh`。脚本使用已有配置，自动启用开机启动和
异常重启；`--dry-run` 可以先预览服务文件。默认运行账户是配置文件的所有者，
也可通过 `--user` 指定。该账户需要能读写配置、数据和证书等相关路径。

使用 `systemctl status postplus.service` 查看状态，
`journalctl -u postplus.service -f` 查看日志，
`sudo systemctl restart postplus.service` 应用已保存的设置。
如果原安装依赖终端环境变量，需要按上面的步骤添加 systemd 环境文件。
