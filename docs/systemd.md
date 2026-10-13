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

## Upgrade an existing installation

Stop `postplus.service`, replace the full release while keeping the existing
configuration and data, then rerun the installer with the same configuration
path and service account. This updates the managed unit, reloads systemd, and
starts the installation. Updating the executable alone leaves the old unit
unchanged. The new unit's `RestartForceExitStatus=75` is required for the
administration **Restart all services** action to relaunch through systemd.
Confirm the installed unit with `systemctl cat postplus.service`.

The unit also runs the native `.postplus-recovery --recover-launcher --config PATH`
helper before every start. It checks a pending launcher upgrade and restores
the previous modules if the new launcher failed before it could acknowledge
readiness. The complete release must include an executable `postplus-update`
accessible to the service account. Rerun this installer once when upgrading an
older managed installation to add `ExecStartPre`; replacing binaries alone
does not add this recovery protection. The installer copies `postplus-update`
to this stable recovery executable; online module upgrades preserve that copy.

The new SMTP default is TCP 25. Upgrading does not rewrite an explicit
`ports.smtp: 2525` in an existing configuration. Change it to 25 in Server
settings and save, or retain controlled forwarding from public TCP 25 to the
configured port. Ensure the service account has privileged-port permission
and allow inbound TCP 25 in the VPS and host firewalls.

## Operate

```sh
systemctl status postplus.service
journalctl -u postplus.service -f
sudo systemctl restart postplus.service
sudo systemctl stop postplus.service
sudo systemctl disable --now postplus.service
```

Saving settings in administration automatically restarts only the affected
services through the native supervisor. Use **Server maintenance → Restart
all services** for a full restart; the installed systemd service brings
PostPlus back automatically. You can still use `systemctl restart` for
operating-system changes, environment overrides, or recovery.

Stopping the service signals the supervisor first and allows up to 130 seconds
for its ordered shutdown. Failed processes restart after five seconds. A
successful **Save and shut down** from administration deliberately leaves the
service stopped until you start it again with
`sudo systemctl start postplus.service`.

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
保存网页设置后，主程序会自动只重启受影响的服务。需要完整重启时，可在后台选择
**重启全部服务**，systemd 会自动重新启动 PostPlus。
`sudo systemctl restart postplus.service` 仍可用于环境变量更改或恢复。
后台的**保存并关闭**会让服务保持停止，需要手动 `systemctl start` 才会恢复。
如果原安装依赖终端环境变量，需要按上面的步骤添加 systemd 环境文件。

升级已有安装时，先停止 `postplus.service`，保留配置和数据并替换完整发行版，
再以原配置路径和服务账户重新运行安装脚本。只替换二进制不会更新旧 unit；
新版 unit 的 `RestartForceExitStatus=75` 是后台“重启全部服务”后自动重新启动的
必要条件。可用 `systemctl cat postplus.service` 核对。

新版 unit 还会在每次启动前执行原生 `.postplus-recovery --recover-launcher --config PATH`
助手。如果升级后的启动器在确认服务就绪前崩溃，下一次启动会恢复旧模块。
发行版必须包含服务账户能够执行的 `postplus-update`。从旧 unit 升级后，需要按原参数
重新运行一次安装脚本，加入 `ExecStartPre`；只替换程序文件不会加入此恢复保护。
安装脚本从 `postplus-update` 创建稳定的恢复副本，在线模块升级会保留该副本。

新版 SMTP 默认端口为 25，但不会自动改写已有配置中显式保存的 `2525`。
请在后台将 SMTP 端口改为 25 并保存，或保留公网 25 到原端口的受控转发；
同时确认特权端口权限以及云端和本机防火墙开放传入 TCP 25。
