# Connect a mail client / 连接邮箱客户端

PostPlus supports standard IMAP, POP3, and authenticated SMTP submission. Use the **Connect mail apps** guide in first-run setup or the **Network** group in administration to copy the settings for your server. The guide follows the form's values; save the configuration and allow the corresponding ports through the host and cloud firewalls before connecting.

PostPlus 支持标准 IMAP、POP3 和经过身份验证的 SMTP 客户端发信。在首次配置的“连接邮箱客户端”或管理后台的“网络”分组中复制服务器参数。参数随表单中的设置更新；连接前需保存配置，并在服务器和云平台防火墙中放行相应端口。

For a mail domain of `example.com` and hostname of `mail.example.com`, a typical secure setup is:

| Setting / 设置 | Value / 值 |
| --- | --- |
| Username / 用户名 | Full mailbox address, such as `you@example.com` / 完整邮箱地址 |
| Password / 密码 | That mailbox's password / 此邮箱的密码 |
| Incoming IMAP / IMAP 收信 | `mail.example.com`, port `993`, SSL/TLS |
| Alternative IMAP / 备用 IMAP | `mail.example.com`, port `143`, STARTTLS |
| Outgoing SMTP / SMTP 发信 | `mail.example.com`, port `587`, STARTTLS, password authentication / 密码验证 |
| Alternative SMTP / 备用 SMTP | `mail.example.com`, port `465`, SSL/TLS, password authentication / 密码验证 |
| Optional POP3 / 可选 POP3 | Port `995`, SSL/TLS; or `110`, STARTTLS |
| Webmail / 网页邮箱 | `https://mail.example.com/` with HTTPS port `443` |

In Thunderbird, Apple Mail, or an IMAP-capable client, choose a manual IMAP account if automatic discovery does not complete. Enter the incoming and outgoing server details independently. The username includes `@example.com` for both servers. Choose **STARTTLS** for port 587 or 143 and **SSL/TLS** for 465 or 993. The one-time setup password and administration API keys are not mailbox passwords.

在 Thunderbird、Apple Mail 或支持 IMAP 的客户端中，如果自动配置未完成，请选择手动配置 IMAP 账号，分别填写收信和发信服务器。两者用户名都包含 `@example.com`。587、143 端口选择 **STARTTLS**；465、993 端口选择 **SSL/TLS**。首次配置密码和管理 API 密钥不能作为邮箱密码。

SMTP port **25** receives messages from other mail servers. Authenticated mail clients normally send through **587** or **465**. IMAP synchronizes folders and messages; POP3 is intended for downloading messages. Submission requires authentication and TLS even when the general configuration allows insecure local authentication. Ports 465, 587, 993, and 995 only start when both TLS certificate and private-key files are configured. Set any of those dedicated ports to `0` to disable its listener.

SMTP **25** 端口接收其他邮件服务器的投递，邮箱客户端通常通过 **587** 或 **465** 端口登录发信。IMAP 同步文件夹和邮件，POP3 用于下载邮件。客户端发信专用服务始终要求身份验证和 TLS。465、587、993、995 端口仅在同时配置 TLS 证书和私钥时启动；将任一专用端口设为 `0` 可禁用它。

Existing custom ports remain unchanged after upgrading. **Apply standard ports** fills SMTP 25, POP3 110, IMAP 143, Webmail 80 or 443, and secure client ports 587, 465, 995, and 993. Those dedicated client ports remain configured but inactive until both TLS certificate and private key are supplied. An explicitly disabled port (`0`) remains disabled until you change it or apply the preset. The preset does not change the administration port or internal service ports. Review the form and save to apply the preset. On Linux, the supplied systemd installation grants permission to bind ports below 1024; a manually started process needs equivalent capability or an appropriate forwarding arrangement.

升级后会保留已有自定义端口。“应用标准端口”填入 SMTP 25、POP3 110、IMAP 143、Webmail 80 或 443，以及安全客户端端口 587、465、995、993。这些专用客户端端口会保留配置，但仅在同时提供 TLS 证书和私钥后启用。显式禁用的端口（`0`）会保持禁用，直到手动修改或点击预设。管理端口和内部服务端口保持原值。检查表单并保存后预设才会生效。Linux 的项目 systemd 安装配置授予绑定 1024 以下端口的权限；手动启动时需提供等效能力或配置适当转发。

## Optional DNS discovery / 可选 DNS 自动发现

In administration, DNS recommendations and server diagnostics are now in the
separate **DNS** group. It keeps all records visible, including matches, and
checks SRV, PTR, and public service TCP connections independently of saving
configuration. See [DNS diagnostics](dns.md) for the scope and limitations.

管理后台将 DNS 推荐记录和服务器诊断放在独立的 **DNS** 分组中，保留已经匹配的记录，并支持独立于保存配置的 SRV、PTR 和公网服务 TCP 检查。检查范围与限制见 [DNS 诊断](dns.md)。

Publish A/AAAA and MX first, then SPF, DKIM, and DMARC as shown in the setup DNS guide. The client guide prepares SRV records from enabled secure listeners. For example, with the standard secure ports:

| Type | Name in the `example.com` zone | Value |
| --- | --- | --- |
| SRV | `_imaps._tcp` | `0 1 993 mail.example.com.` |
| SRV | `_submission._tcp` | `0 1 587 mail.example.com.` |
| SRV | `_submissions._tcp` | `0 1 465 mail.example.com.` |
| SRV | `_autodiscover._tcp` | `0 1 443 mail.example.com.` |

SRV fields are **priority 0**, **weight 1**, the enabled listener's **port**, and the mail hostname as **target**. The target must have its own direct A/AAAA records. Only add `_autodiscover._tcp` when HTTPS Webmail is exposed on port 443 and both secure incoming and authenticated outgoing services are available. DNS-only mode is required for mail protocol traffic. These are optional records: a client can always use the manual hostname and ports. The setup DNS check covers A, AAAA, MX, SPF, DKIM, and DMARC; it does not validate these SRV records or test public TCP reachability.

先按配置引导发布 A/AAAA 和 MX，再配置 SPF、DKIM、DMARC。客户端引导根据已启用的安全监听端口生成 SRV 记录。SRV 字段依次为**优先级 0**、**权重 1**、实际监听**端口**、邮件主机名**目标**。目标需有直接 A/AAAA 记录。仅在 HTTPS Webmail 使用公网 443 端口，且安全收信与客户端发信服务均启用时发布 `_autodiscover._tcp`。邮件协议需使用仅 DNS 模式。这些记录是可选项；客户端始终可以手动填写主机名和端口。配置页面的 DNS 检查仅覆盖 A、AAAA、MX、SPF、DKIM、DMARC，不验证 SRV 记录或公网 TCP 连通性。

PostPlus serves Thunderbird-style autoconfig at `https://mail.example.com/.well-known/autoconfig/mail/config-v1.1.xml` and POX Autodiscover at `https://mail.example.com/autodiscover/autodiscover.xml`. Autoconfig accepts an `emailaddress` query parameter; Autodiscover accepts a POST containing the mailbox address. These endpoints describe standard IMAP/POP3/SMTP settings; they do not implement Exchange. Client discovery support varies, so manual setup may still be needed.

PostPlus 在邮件主机名下提供 Thunderbird 格式自动配置和 POX Autodiscover，地址如上。前者通过 `emailaddress` 查询参数接收邮箱地址，后者通过 POST 接收包含邮箱地址的请求。这些接口描述标准 IMAP、POP3、SMTP 参数，不提供 Exchange 功能。客户端自动发现能力不同，必要时仍需手动配置。

The certificate must cover the mail hostname. The built-in certificate flow requests that hostname only, so the guide does not suggest CNAME aliases for `autoconfig.example.com` or `autodiscover.example.com`: accessing those names needs certificate coverage for them as well. Publishing an alias alone does not meet that requirement.

证书必须覆盖邮件主机名。内置证书流程仅申请该主机名，因此引导不会建议为 `autoconfig.example.com` 或 `autodiscover.example.com` 添加 CNAME：访问这些别名还需要证书覆盖对应名称，仅添加 DNS 别名无法满足这一要求。
