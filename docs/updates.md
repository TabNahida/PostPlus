# Upgrading PostPlus / 升级 PostPlus

Administration → Server settings → **Update PostPlus** checks the latest stable
Release from `TabNahida/PostPlus`. Review the version and affected files, download
the update, then choose **Apply prepared update**. Downloading leaves services
running. The update verifies HTTPS, the official release URL, SHA-256 hashes,
platform and service contract before installing anything.

管理后台 → 服务器设置 → **升级 PostPlus** 可检查官方最新正式 Release。
先查看版本和变化文件，下载后再应用。下载期间服务继续运行；应用前检查
HTTPS、官方发布来源、SHA-256、平台和服务接口兼容性。

Source fingerprints identify changed components, so a build timestamp alone
does not replace an unchanged binary. Complete packages include their installed
component baseline in `postplus-update.json`, so this also works for the first
online upgrade after installation. Changes to shared core code or build
dependencies affect its consumers. Changed web resources restart Webmail and
administration. Other unchanged services keep running. Configuration, mailbox
and account databases, delivery queues, certificates, and private keys are
excluded from the updater's file allowlist.

更新按源码指纹判断模块是否改变，编译时间变化不会单独触发替换。完整安装包带有
`postplus-update.json` 组件基线，首次在线升级也能判断未变模块。公共核心代码
或依赖改变时，相关模块也会更新。网页资源变化会重启 Webmail 和后台，其他未变
服务继续运行。配置、邮件、账户、队列、证书及私钥不在升级文件范围内。

Affected services briefly close their connections while files are replaced.
The supervisor checks readiness before committing the update. Failed startup
restores the previous modules and attempts to restart them. A launcher change
requires the whole service group to restart: the managed systemd installation
relaunches automatically; Windows uses a private native helper; a Unix terminal
installation replaces the launcher through `exec`. No shell, Python, curl or
archive extraction tool is required at runtime.

变化的服务替换文件时会短暂断开连接，启动检查通过后才完成升级。启动失败会
恢复旧模块并尝试重启。启动器变化需要整体重启：项目安装的 systemd 服务会
自动重启；Windows 使用原生升级助手；Unix 终端启动使用 `exec` 重新启动。

For an existing systemd installation, install the complete release containing
this feature, then rerun `sudo bash scripts/install-systemd.sh` once with the
same configuration path and service account. The updated unit runs
`.postplus-recovery --recover-launcher --config PATH` through `ExecStartPre` before
each start. If an upgraded launcher crashes before entering its startup checks
or acknowledging readiness, the next start restores the previous modules and
version record. Verify this entry with `systemctl cat postplus.service`.
Replacing executable files alone leaves an older unit without this protection.
The installer keeps this recovery copy outside the online module inventory, so
it remains executable even if the upgraded launcher or updater cannot run.
Rerunning the installer refreshes the recovery copy for a new updater contract.

已有 systemd 安装需要先安装包含本功能的完整发行版，再按原配置路径和服务账户
重新运行一次 `sudo bash scripts/install-systemd.sh`。新版 unit 会通过
`ExecStartPre` 在每次启动前执行 `.postplus-recovery --recover-launcher --config PATH`。
如果新启动器在进入启动检查或确认就绪前崩溃，下次启动会恢复旧模块和版本记录。
请用 `systemctl cat postplus.service` 确认该项；只替换程序文件不会更新旧 unit。
安装脚本保留一份不参与在线替换的恢复助手，即使新版启动器或升级助手无法执行，
旧助手仍可恢复原模块。重新运行安装脚本会刷新这份恢复助手。

If administration restarts, sign in again and use **Refresh update status**.
A disconnected page does not mean the upgrade succeeded. Backups, configuration
saves, shutdown and upgrade operations are mutually exclusive. The service user
needs write permission to the installed binaries, web directory and data
directory. An installation owned by another account must be updated by its
administrator or have its ownership corrected before automatic updates work.

后台重启后需要重新登录并刷新升级状态，页面断开不代表升级成功。升级与备份、
保存配置、停机互斥。运行服务的账户必须能写入程序、网页和数据目录；若文件
由其他账户所有，需要管理员调整所有权或执行升级。

The published 0.2.1 binary has no updater. Install a release containing this
feature once while keeping the existing configuration and data. Subsequent
releases must include `postplus-update.json`, module assets and `SHA256SUMS`.
Older releases containing only complete archives remain manual upgrades. Do not
overwrite a published release tag to add updater files.

已发布的 0.2.1 没有自动升级功能，需要先手动安装一次包含本功能的新版本，保留
原配置和数据。之后的 Release 会提供模块清单、模块文件和摘要。只有完整压缩包
的旧 Release 继续使用手动升级。

## Administration API

These endpoints use the existing administrator session with CSRF, or the
administration Bearer API key on HTTPS/loopback:

| Request | Purpose |
| --- | --- |
| `GET /api/admin/update` | Current installed version, availability and latest job |
| `POST /api/admin/update/check` with `{}` | Latest stable version and changed-file plan |
| `POST /api/admin/update/stage` with `{"version":"0.3.0"}` | Schedule download of the reviewed release |
| `POST /api/admin/update/apply` with `{"job_id":"..."}` | Apply a verified prepared update |
| `GET /api/admin/update?job_id=...` | Poll a specific job |

Job states are `pending_download`, `downloading`, `staged`, `pending_apply`,
`applying`, `complete` and `failed`. `rolled_back: true` reports restored files
and services. Checking uses `update_available` for a newer release and `supported`
for a compatible module manifest. `available` describes the supervisor feature.
`files`, `services`, `download_bytes` and `requires_launcher_restart` describe
the update plan. A changed latest Release requires checking it again.
