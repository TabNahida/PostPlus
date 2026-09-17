"use strict";
// Only an explicit choice is persisted. A fresh browser always starts in English.
window.PostPlusI18n = (() => {
  const chinese = {
    "PostPlus · Your mail, in order":"PostPlus · 邮件，井然有序", "PostPlus home":"PostPlus 首页", "YOUR MAIL. YOUR SPACE.":"你的邮箱，你的空间。", "A place for every message.":"每一封来信，都有自己的位置。", "From the first hello to the next good news.":"从第一句问候，到下一个好消息。", "C++20 · OPEN SOURCE":"C++20 · 开源", "Language":"语言", "WELCOME BACK":"欢迎回来", "Sign in to your mailbox":"回到你的邮箱", "Use the account provided by your administrator.":"使用管理员分配的账号登录。", "Email address":"邮箱地址", "Password":"密码", "Sign in":"登录", "Need an account or a password reset? Contact your mail administrator.":"需要账号或重置密码？请联系邮箱管理员。", "Simple communication. Your control.":"简单沟通，自在掌控。", "Compose":"写邮件", "WORKSPACE":"工作空间", "Mailbox navigation":"邮箱导航", "Inbox":"收件箱", "Administration":"管理后台", "Make room for what matters.":"留一点空间，给重要的消息。", "Sign out":"退出登录", "YOUR INBOX":"你的收件箱", "Ready":"准备就绪", "Refresh":"刷新", "Message list":"邮件列表", "All messages":"全部邮件", "No messages yet":"还没有新邮件", "New messages will appear here.":"新消息到达后，会出现在这里。", "Message content":"邮件内容", "A LITTLE ROOM TO READ":"留一点阅读的空间", "Open a message. Start a conversation.":"打开一封邮件，开始一段对话。", "Choose a message from the list.":"从列表选择一封来信。", "← Back to messages":"← 返回列表", "Delete message":"删除邮件", "From":"发件人", "To":"收件人", "Date":"时间", "View raw message / MIME":"查看原始邮件 / MIME", "SERVER ADMINISTRATION":"服务器管理", "Messages":"邮件总数", "Stored mail":"已存储的来信", "Queued":"待投递", "Awaiting delivery":"等待后台投递处理", "Storage":"邮件空间", "Mail content size":"当前邮件内容大小", "User accounts":"用户账号", "Manage accounts and administrator access.":"管理用户账号与管理员权限。", "＋ Create user":"＋ 新建用户", "Role":"角色", "Actions":"操作", "Delivery queue":"投递队列", "Up to 100 pending or quarantined jobs.":"最多显示 100 个待处理或隔离任务。", "Recipient":"收件人", "Status":"状态", "Attempts":"尝试次数", "Reason":"原因", "No messages in the queue.":"当前没有排队的邮件。", "Service logs":"服务日志", "Recent server events, newest first.":"最近的服务器事件，按时间倒序显示。", "Refresh logs":"刷新日志", "Service":"服务", "Level":"级别", "All services":"全部服务", "All levels":"全部级别", "Debug":"调试", "Info":"信息", "Warning":"警告", "Error":"错误", "Time":"时间", "Process ID":"进程 ID", "Event":"事件", "No events match these filters.":"没有符合筛选条件的日志。", "NEW MESSAGE":"新邮件", "Compose a message":"写一封邮件", "Close compose window":"关闭写邮件窗口", "Separate email addresses with commas":"多个邮箱使用逗号分隔", "Subject":"主题", "What is it about?":"关于……", "Message":"正文", "Hello,":"你好，", "Send from your signed-in account":"以当前账号发送", "Send message ↗":"发送邮件 ↗", "ACCOUNT MANAGEMENT":"账号管理", "Create user":"新建用户", "Close account window":"关闭账号窗口", "New password":"新密码", "At least 8 characters.":"至少 8 个字符。", "Grant administrator access":"授予管理员权限", "Cancel":"取消", "Save account":"保存账号", "Delete this message?":"删除这封邮件？", "The message will be permanently deleted from the server.":"邮件将从服务器永久删除。", "Delete permanently":"永久删除", "Cannot connect to the server. Check your connection and try again.":"暂时无法连接服务器，请检查网络后重试。", "The server returned an unreadable response.":"服务器返回了无法读取的响应。", "Your session has expired. Please sign in again.":"登录已过期，请重新登录。", "The request failed. Please try again.":"请求失败，请稍后重试。", "Message #{id}":"邮件 #{id}", "Unread, {title}":"未读，{title}", "Read":"已读", "Unread":"未读", "{count} message":"{count} 封邮件", "{count} messages":"{count} 封邮件", "Syncing…":"正在同步…", "Updated at {time}":"更新于 {time}", "Sync failed":"同步失败", "(No subject)":"（无主题）", "(Empty message)":"（空白邮件）", "Enter at least one recipient email address.":"请填写至少一个收件人邮箱。", "Your message has been queued for delivery.":"邮件已加入投递队列。", "Message deleted.":"邮件已删除。", "Administrator":"管理员", "User":"普通用户", "Reset password":"重置密码", "Reset password for {username}":"重置 {username} 的密码", "Pending":"等待投递", "Quarantined":"已隔离", "Password updated. Sign in with your new password.":"密码已更新，请使用新密码登录。", "Password updated. This user's sessions have been revoked.":"密码已更新，该用户的登录会话已失效。", "User account created.":"用户账号已创建。", "Loading logs…":"正在读取日志…", "Showing {count} recent events.":"显示最近 {count} 条事件。", "Showing {count} recent events. Older events are omitted.":"显示最近 {count} 条事件，更早的事件已省略。",
    "Use application/json for this request.":"请求必须使用 JSON 格式。", "A JSON object is required.":"请求需要一个 JSON 对象。", "Enter a full email address.":"请输入完整的邮箱地址。", "Passwords must contain at least 8 characters.":"密码必须至少包含 8 个字符。", "Invalid request data.":"请求数据无效。", "A required service is unavailable. Please retry.":"所需的服务暂不可用，请稍后重试。", "Too many sign-in attempts. Try again in one minute.":"登录尝试过多，请在一分钟后重试。", "HTTPS is required to access your account.":"必须使用 HTTPS 访问账号。", "Sign in to continue.":"请先登录。", "Security token is missing or expired. Refresh this page.":"安全令牌缺失或已过期，请刷新页面。", "Session capacity reached. Please try again later.":"当前登录会话已达上限，请稍后重试。", "Page not found.":"找不到页面。", "Invalid message ID.":"邮件标识无效。", "Administrator access is required.":"需要管理员权限。", "Account addresses must use the configured server domain.":"账号地址必须使用服务器配置的域名。", "API route not found.":"找不到 API 接口。", "Provide between 1 and 100 recipient addresses.":"请输入 1 至 100 个收件人地址。", "Recipient addresses must be strings.":"收件人地址格式无效。", "Invalid recipient address.":"收件人地址无效。", "External delivery is unavailable until an administrator configures a smarthost.":"管理员配置出站中继服务器后才能发送外部邮件。", "The message contains invalid headers or content.":"邮件头或正文内容无效。", "The encoded message exceeds the server size limit.":"编码后的邮件超出服务器大小限制。", "The message was rejected by the server mail filter.":"邮件被服务器过滤系统拒绝。", "Unable to load messages.":"无法读取邮件列表。", "Message not found.":"找不到邮件。", "Unable to update message flags.":"无法更新邮件标记。", "Unable to delete message.":"无法删除邮件。", "Unable to load accounts.":"无法读取用户账号。", "Unable to load server statistics.":"无法读取服务器统计信息。", "Unable to inspect the delivery queue.":"无法读取投递队列。", "Unable to create account. This address may already exist.":"无法创建账号，该邮箱地址可能已存在。", "Unable to change password.":"无法修改密码。", "Unable to validate recipients.":"无法验证收件人。", "The message scanning service is unavailable.":"邮件扫描服务暂不可用。", "Unable to queue your message.":"无法将邮件加入投递队列。", "Invalid email address or password.":"邮箱地址或密码错误。", "Invalid username or password.":"邮箱地址或密码错误。", "Unable to load service logs.":"无法读取服务日志。", "Invalid log filter.":"日志筛选条件无效。", "Missing text field: {field}":"缺少文本字段：{field}", "Field is too long: {field}":"字段过长：{field}", "A local recipient account does not exist: {recipient}":"本地收件人账号不存在：{recipient}",
    "PostPlus · First-run setup":"PostPlus · 首次配置", "FIRST-RUN SETUP":"首次配置", "Set up your mail server":"配置你的邮件服务器", "Choose your domain, create the first administrator, and connect your services.":"填写域名，创建首个管理员账号，并配置各项服务。", "Server identity":"服务器信息", "Mail domain":"邮箱域名", "Use the part after @ in your email addresses. For example, example.com.":"填写邮箱地址中 @ 后面的域名，例如 example.com。", "Mail data folder":"邮件数据目录", "PostPlus stores mail, accounts, and service logs in this folder.":"PostPlus 在此目录保存邮件、账号和服务日志。", "First administrator":"首个管理员", "Administrator email":"管理员邮箱", "Use an address on the mail domain above.":"使用上方邮箱域名下的地址。", "Create a password":"设置密码", "Confirm password":"确认密码", "Connections and security":"连接与安全", "Connection mode":"连接模式", "Local only (this computer)":"仅本机访问", "TLS (secure network access)":"TLS（安全网络访问）", "Local mode listens on this computer only. Choose TLS to allow network access.":"本地模式仅允许此电脑访问。需要通过网络访问时请选择 TLS。", "Listen address":"监听地址", "127.0.0.1 is local only. Use 0.0.0.0 to listen on all IPv4 interfaces.":"127.0.0.1 仅允许本机访问；0.0.0.0 监听所有 IPv4 网卡。", "TLS certificate file":"TLS 证书文件", "TLS private key file":"TLS 私钥文件", "Enter paths to existing PEM files on the server. The private key must be readable by PostPlus.":"填写服务器上已有 PEM 文件的路径，确保 PostPlus 可以读取私钥。", "Service ports":"服务端口", "Defaults avoid privileged ports. Use different ports for each service.":"默认端口无需特权权限，每项服务必须使用不同端口。", "Authentication":"认证服务", "Mail storage":"邮件存储", "Mail filter":"邮件过滤", "Mail transfer":"邮件传输", "Webmail and administration":"Webmail 与管理后台", "Delivery lock":"投递锁", "Optional services":"可选服务", "Outgoing mail relay":"出站邮件中继", "A relay (smarthost) sends mail to other domains. Leave blank for local mail only.":"中继服务器（smarthost）负责向其他域名发送邮件。仅使用本地邮件时可留空。", "Relay host":"中继服务器地址", "Port":"端口", "Relay encryption":"中继加密方式", "STARTTLS (recommended)":"STARTTLS（推荐）", "Implicit TLS":"隐式 TLS", "None":"无", "Relay username":"中继用户名", "Password environment variable":"密码环境变量名称", "Set this environment variable before starting PostPlus. Do not enter the relay password here.":"启动 PostPlus 前设置此环境变量，此处不要填写中继密码。", "ClamAV antivirus":"ClamAV 杀毒服务", "Connect an existing ClamAV daemon. Leave the host blank to skip antivirus integration.":"连接已有的 ClamAV 服务。如不接入杀毒服务，可将地址留空。", "ClamAV host":"ClamAV 地址", "Save configuration and start":"保存配置并启动", "Loading setup…":"正在加载配置…", "Saving configuration…":"正在保存配置…", "Your server is configured":"服务器配置完成", "PostPlus is starting. Open Webmail to sign in with your administrator account.":"PostPlus 正在启动。打开 Webmail 后，使用管理员账号登录。", "Open Webmail and administration":"打开 Webmail 与管理后台", "Setup link required. Open the complete setup URL printed by the PostPlus launcher.":"需要配置链接，请打开 PostPlus 主程序输出的完整配置网址。", "Passwords do not match.":"两次输入的密码不一致。", "The setup link is invalid or expired. Use the latest link from the launcher.":"配置链接无效或已过期，请使用主程序输出的最新链接。", "Check the highlighted fields and try again.":"请检查表单字段后重试。", "Enter a valid mail domain.":"请输入有效的邮箱域名。", "The administrator address must belong to your mail domain.":"管理员地址必须属于配置的邮箱域名。", "Choose a password with at least 8 characters.":"请设置至少 8 个字符的密码。", "Enter a valid listen address.":"请输入有效的监听地址。", "Choose a connection mode.":"请选择连接模式。", "Network access requires TLS and secure authentication.":"网络访问必须启用 TLS 和安全认证。", "The TLS certificate or key could not be loaded. Check the server paths and permissions.":"无法加载 TLS 证书或私钥，请检查服务器路径与读取权限。", "The data folder is invalid or cannot be used. Choose an empty folder.":"数据目录无效或不可使用，请选择空目录。", "Each service must use a different port.":"每项服务必须使用不同端口。", "A service port conflicts with the setup server.":"服务端口与配置页面服务冲突。", "Enter a valid environment variable name.":"请输入有效的环境变量名称。", "Choose a valid relay encryption mode. Authentication requires TLS.":"请选择有效的中继加密方式，使用认证时必须启用 TLS。", "Setup is only available from this computer.":"配置页面仅允许在本机访问。", "This setup request is not from the setup page. Reopen the launcher URL.":"配置请求来源无效，请重新打开主程序提供的网址。", "Setup is already saving. Wait for it to finish.":"配置正在保存，请等待完成。", "This server has already been configured.":"此服务器已完成配置。", "The setup request is invalid. Refresh using the launcher URL.":"配置请求无效，请使用主程序提供的网址刷新。", "Could not create the server data or administrator. Check the launcher output and folder permissions.":"无法创建服务器数据或管理员，请检查主程序输出和目录权限。", "Could not save the configuration file. Check the launcher output and file permissions.":"无法保存配置文件，请检查主程序输出和文件权限。", "Setup failed. Check the launcher output before trying again.":"配置失败，请检查主程序输出后重试。", "Ports must be whole numbers from 1 to 65535.":"端口必须为 1 至 65535 之间的整数。"
  };
  Object.assign(chinese, {"The email address or password is incorrect.":"邮箱地址或密码错误。", "Invalid log limit.":"日志数量限制无效。", "Invalid log filters.":"日志筛选条件无效。", "Invalid log filters or limit.":"日志筛选条件或数量限制无效。", "A service port is unavailable. Choose another port or check permissions.":"服务端口不可用，请选择其他端口或检查权限。"});
  Object.assign(chinese, {
  "Webmail": "网页邮箱",
  "PostPlus · Administration": "PostPlus · 管理后台",
  "Overview": "概览",
  "Server settings": "服务器设置",
  "YOUR SERVER. YOUR CONTROL.": "你的服务器，由你掌控。",
  "A good home for your mail.": "让每封邮件，都有归处。",
  "Accounts, delivery, and settings. All in one place.": "账号、投递与配置，在这里轻松管理。",
  "Sign in as administrator": "管理员登录",
  "Use the administrator account created during setup.": "使用首次配置时创建的管理员账号。",
  "This is your server's administration portal. Open the separate Webmail address to read your email.": "这是服务器管理后台。阅读邮件请打开独立的 Webmail 地址。",
  "Administration navigation": "管理后台导航",
  "A little care. A better mail day.": "用心管理，让沟通更轻松。",
  "YOUR MAIL, IN GOOD HANDS": "用心照料你的邮件",
  "Welcome to your mail server.": "欢迎来到你的邮件服务器。",
  "Create accounts, check delivery, and make this space your own.": "创建账号、检查投递，配置属于你的邮件空间。",
  "Configure your server ↗": "配置服务器 ↗",
  "Your next steps": "接下来可以做什么",
  "Invite your people": "为伙伴创建邮箱",
  "Create a mailbox for each person who needs an account.": "为每位需要账号的伙伴创建邮箱。",
  "Connect your domain": "连接你的域名",
  "Review network, TLS, and outgoing mail settings.": "检查网络、TLS 与出站邮件配置。",
  "See what is happening": "了解服务运行情况",
  "Check service logs when you need a closer look.": "通过服务日志查看运行详情。",
  "Open Webmail ↗": "打开 Webmail ↗",
  "Webmail has its own address and sign-in session.": "Webmail 使用独立的网址和登录会话。",
  "Make your server work for you.": "让服务器适合你的需要。",
  "Start with the basics. Open the advanced groups when you need more control.": "从基本选项开始，需要时再展开高级设置。",
  "Loading settings…": "正在读取设置…",
  "Saving restarts all services and signs you out. Your mail and accounts are kept.": "保存后将重启所有服务并退出登录，邮件和账号会保留。",
  "Save and restart": "保存并重启",
  "Settings saved": "设置已保存",
  "PostPlus is restarting. Wait a few seconds, then open administration and sign in again.": "PostPlus 正在重启。稍等几秒后打开管理后台，重新登录。",
  "Open administration ↗": "打开管理后台 ↗",
  "No settings have changed.": "设置没有变化。",
  "WELCOME TO POSTPLUS": "欢迎使用 POSTPLUS",
  "Let's make it yours.": "从这里，开始你的邮件空间。",
  "Copy the one-time setup password from the terminal running PostPlus.": "复制运行 PostPlus 的终端中显示的一次性配置密码。",
  "One-time setup password": "一次性配置密码",
  "Unlock setup ↗": "进入配置 ↗",
  "This password only unlocks setup. You will create your administrator password next.": "此密码仅用于进入配置页面，接下来你将创建管理员密码。",
  "Administration and Webmail have separate addresses. Administration defaults to port 8081; Webmail defaults to 8080.": "管理后台和 Webmail 使用独立地址，默认端口分别为 8081 和 8080。",
  "Advanced settings": "高级设置",
  "Defaults work for a first local mailbox. You can change these options later in administration.": "默认值适合首次体验本地邮箱，之后可在管理后台修改这些选项。",
  "PostPlus is starting. Open administration to add users and review settings, or open Webmail to read your mail.": "PostPlus 正在启动。打开管理后台添加用户和检查设置，或打开 Webmail 阅读邮件。",
  "General": "基本信息",
  "Your domain and the folders that make this server yours.": "配置服务器的邮箱域名与基本信息。",
  "Network": "网络",
  "Separate addresses and ports for administration, Webmail, and mail clients.": "管理后台、Webmail 和邮件客户端分别使用独立的地址与端口。",
  "Security": "安全",
  "Certificates, authentication, and connection protection.": "配置证书、身份认证与连接保护。",
  "Connection and message limits": "连接与邮件限制",
  "Choose sensible limits for mail clients and message uploads.": "设置邮件客户端连接数与邮件上传限制。",
  "Outgoing mail": "出站邮件",
  "Connect a relay to send mail to other domains.": "连接中继服务器，以便向其他域名发送邮件。",
  "Mail filtering": "邮件过滤",
  "Choose how suspicious mail and antivirus failures are handled.": "配置可疑邮件过滤与杀毒服务。",
  "Storage and limits": "存储与配额",
  "Set message sizes, account quotas, and delivery limits.": "设置邮件大小、账号配额与投递限制。",
  "Logging": "日志",
  "Keep useful service events without using unlimited disk space.": "保留需要的服务事件，并限制日志占用的磁盘空间。",
  "Server folders": "服务器目录",
  "Review where your server stores its data and web pages.": "查看服务器存储数据与网页文件的位置。",
  "Enabled": "启用",
  "Disabled": "禁用",
  "Managed by the server. Change this in the configuration file while PostPlus is stopped.": "由服务器管理。请停止 PostPlus 后，在配置文件中修改。",
  "A password is saved. Leave blank to keep it.": "已保存密码，留空可保留现有密码。",
  "No password is saved. Leave blank to use the environment variable.": "尚未保存密码，留空将使用环境变量。",
  "Check the value for {field}.": "请检查“{field}”的值。",
  "Domain used for local recipient addresses; changing it does not rename existing accounts.": "本地收件人地址使用的域名，修改后不会自动重命名已有账号。",
  "Mail and Webmail listening address": "邮件协议与 Webmail 监听地址",
  "Use 127.0.0.1 for local use or 0.0.0.0 to accept IPv4 connections from other computers.": "127.0.0.1 仅供本机使用，0.0.0.0 可接受其他电脑的 IPv4 连接。",
  "Administration listening address": "管理后台监听地址",
  "Keep 127.0.0.1 unless remote administration is needed; public access requires TLS.": "不需要远程管理时请保留 127.0.0.1，对外开放必须启用 TLS。",
  "Every service needs a different port. Internal services listen on loopback.": "每项服务必须使用不同端口，内部服务仅监听本机回环地址。",
  "Delivery lock port": "投递锁端口",
  "Loopback port used to prevent duplicate delivery workers.": "通过本机回环端口防止重复启动投递进程。",
  "Allow local plaintext authentication": "允许本机明文认证",
  "Only loopback clients may authenticate without TLS. Disable for deployment.": "仅本机回环客户端可不通过 TLS 认证。正式部署时请关闭。",
  "Readable PEM certificate chain; paths are relative to the configuration file.": "可读取的 PEM 证书链，路径相对于配置文件所在目录。",
  "Matching unencrypted PEM private key. File contents are never exposed by this API.": "与证书匹配的未加密 PEM 私钥，此接口不会返回文件内容。",
  "Authentication attempts per connection": "每次连接允许的认证次数",
  "Password hashing iterations": "密码哈希迭代次数",
  "Applies to newly created or changed passwords.": "应用于新建或修改后的密码。",
  "Maximum password bytes": "密码最大字节数",
  "Concurrent connections per service": "每项服务的并发连接数",
  "Each active connection uses a worker thread.": "每条活动连接使用一个工作线程。",
  "Network timeout (seconds)": "网络超时时间（秒）",
  "SMTP message upload timeout (seconds)": "SMTP 邮件上传超时（秒）",
  "Total time allowed to upload one message.": "上传单封邮件允许使用的总时间。",
  "Maximum message bytes": "单封邮件最大字节数",
  "10 MiB by default.": "默认为 10 MiB。",
  "Maximum recipients per message": "每封邮件的最大收件人数",
  "Maximum bytes per mailbox": "每个邮箱的最大字节数",
  "Maximum messages per mailbox": "每个邮箱的最大邮件数",
  "Maximum queued message bytes": "队列邮件的最大总字节数",
  "Maximum queued messages": "队列最大邮件数",
  "Outgoing relay host": "出站中继服务器地址",
  "Leave blank for local mail only. Use your provider's SMTP relay hostname.": "仅使用本地邮件时留空。需要对外发送时填写服务商的 SMTP 中继主机名。",
  "Outgoing relay port": "出站中继端口",
  "Outgoing relay encryption": "出站中继加密方式",
  "Authenticated relays require STARTTLS or implicit TLS.": "需要认证的中继必须使用 STARTTLS 或隐式 TLS。",
  "Outgoing relay timeout (seconds)": "出站中继超时（秒）",
  "Outgoing relay username": "出站中继用户名",
  "Relay password environment variable": "中继密码环境变量",
  "An explicitly set environment variable takes precedence over the saved password.": "已设置的环境变量优先于保存的密码。",
  "Outgoing relay password": "出站中继密码",
  "Leave blank to keep the saved password. New passwords are saved in a private secret file.": "留空保留现有密码。新密码保存在受保护的密钥文件中。",
  "Leave blank to use baseline filtering only. Install and run clamd separately.": "留空仅使用基础过滤。需要杀毒时，请单独安装并运行 clamd。",
  "ClamAV port": "ClamAV 端口",
  "ClamAV scan timeout (seconds)": "ClamAV 扫描超时（秒）",
  "Spam rejection score": "垃圾邮件拒收分值",
  "Messages at or above this score are rejected.": "达到或超过此分值的邮件将被拒收。",
  "Blocked terms": "拦截词",
  "One term per line; a match rejects the message.": "每行一个词，命中即拒收邮件。",
  "Weighted spam rules": "垃圾邮件计分规则",
  "JSON array of objects with term and positive weight.": "JSON 数组，每项包含 term（匹配词）与正数 weight（分值）。",
  "Minimum log level": "最低日志级别",
  "Maximum bytes per log file": "每个日志文件最大字节数",
  "Rotated log files per service": "每项服务保留的轮转日志数",
  "Configured during initial setup. Stop PostPlus and follow the configuration guide before changing filesystem paths.": "在首次配置时设置。修改目录前请停止 PostPlus，并按照配置指南操作。",
  "data_dir": "数据目录",
  "web_root": "网页文件目录",
  "log_dir": "日志目录",
  "starttls": "STARTTLS 加密",
  "implicit": "隐式 TLS",
  "none": "无加密",
  "debug": "调试",
  "info": "信息",
  "warn": "警告",
  "error": "错误",
  "The setup password is incorrect or expired. Copy the latest one-time password from the terminal.": "配置密码错误或已过期，请复制终端中最新的一次性密码。",
  "Configuration changed since it was opened. Reload before saving.": "配置已被其他操作修改，请重新加载页面后再保存。",
  "Cannot replace the configuration file. Check permissions.": "无法替换配置文件，请检查文件权限。",
  "This path cannot be changed through the web interface.": "无法通过网页修改此目录。",
  "Provide at most 1000 blocked terms.": "拦截词不能超过 1000 个。",
  "Blocked terms cannot be empty.": "拦截词不能为空。",
  "Provide at most 1000 spam rules.": "垃圾邮件规则不能超过 1000 条。",
  "Spam rules require term and weight.": "垃圾邮件规则必须包含 term 与 weight。",
  "Each spam rule needs a term and a weight greater than 0 and at most 1000.": "每条规则需要匹配词，且分值必须大于 0、小于或等于 1000。",
  "Enter a valid ASCII mail domain, such as example.com.": "请输入有效的 ASCII 邮箱域名，例如 example.com。",
  "Provide both a TLS certificate and private key.": "请同时填写 TLS 证书与私钥。",
  "The listening address must be an IPv4 or IPv6 address.": "监听地址必须是 IPv4 或 IPv6 地址。",
  "Public listening addresses require TLS and disabled insecure authentication.": "对外监听必须启用 TLS 并关闭明文认证。",
  "Provide TLS files or explicitly enable local plaintext authentication.": "请配置 TLS 文件，或明确允许本机明文认证。",
  "TLS files must be readable PEM files with a matching, unencrypted private key.": "TLS 文件必须是可读取的 PEM 文件，证书与未加密私钥必须匹配。",
  "Every PostPlus service must use a different port.": "每项 PostPlus 服务必须使用不同端口。",
  "Hostnames and usernames must not exceed 253 bytes.": "主机名和用户名不能超过 253 字节。",
  "Use a valid environment variable name for the relay password.": "请为中继密码填写有效的环境变量名称。",
  "An authenticated relay requires TLS.": "需要认证的中继必须使用 TLS。",
  "Storage byte limits must be at least the maximum message size.": "存储字节数限制不能小于单封邮件大小限制。",
  "Configuration must be a regular file no larger than 1 MiB.": "配置必须是小于或等于 1 MiB 的普通文件。",
  "Cannot read configuration file.": "无法读取配置文件。",
  "Check the configuration field: {field}.": "请检查配置字段：{field}。",
  "admin port": "管理后台端口",
  "web port": "Webmail端口",
  "smtp port": "SMTP端口",
  "pop3 port": "POP3端口",
  "imap port": "IMAP端口",
  "auth port": "认证服务端口",
  "storage port": "邮件存储端口",
  "filter port": "邮件过滤端口",
  "transfer port": "邮件传输端口"
});
  Object.assign(chinese, {"Remove the saved relay password":"删除已保存的中继密码"});
  Object.assign(chinese, {"Administration port":"管理后台端口","Webmail port":"Webmail 端口","SMTP port":"SMTP 端口","POP3 port":"POP3 端口","IMAP port":"IMAP 端口","Authentication port":"认证服务端口","Mail storage port":"邮件存储端口","Mail filter port":"邮件过滤端口","Mail transfer port":"邮件传输端口"});
  Object.assign(chinese, {"Web session lifetime (seconds)":"网页登录会话时长（秒）","Applies to both administration and Webmail.":"同时应用于管理后台与 Webmail。","Maximum web sessions per service":"每项 Web 服务的最大会话数"});
  Object.assign(chinese, {"Save settings":"保存设置","Changes take effect after you restart PostPlus. Saving keeps the current services running.":"重启 PostPlus 后更改才会生效。保存不会中断正在运行的服务。","Restart PostPlus in its terminal: press Ctrl+C, then run the same launch command again. After startup, use the updated addresses below.":"在运行 PostPlus 的终端按 Ctrl+C，然后重新执行原来的启动命令。启动完成后，使用下方更新后的地址访问。"});
  Object.assign(chinese,{"Continue editing":"继续编辑"});
  Object.assign(chinese,{"Saved changes are waiting for a restart. Stop PostPlus with Ctrl+C and launch it again to apply them.":"保存的更改正在等待重启。请按 Ctrl+C 停止 PostPlus，再次启动后生效。"});
  Object.assign(chinese,{"Adjust service ports":"调整服务端口","Show advanced options":"显示高级选项"});
  Object.assign(chinese, {
  "Sent": "已发送",
  "Drafts": "草稿箱",
  "Trash": "回收站",
  "Junk": "垃圾邮件",
  "Archive": "归档",
  "Mailbox storage": "邮箱空间",
  "This folder is empty": "此文件夹为空",
  "Messages in this folder will appear here.": "此文件夹中的邮件会显示在这里。",
  "Edit draft": "编辑草稿",
  "Move message to": "移动邮件至",
  "Move to…": "移动至…",
  "Move to Trash": "移至回收站",
  "Discard changes": "放弃更改",
  "Save draft": "保存草稿",
  "Draft saved": "草稿已保存",
  "Unsaved changes": "更改尚未保存",
  "Save or discard your current changes before opening another draft.": "请先保存或放弃当前更改，再打开另一封草稿。",
  "Message moved to {folder}.": "邮件已移至{folder}。",
  "{used} of {limit}": "已使用 {used} / {limit}",
  "MAIL INSPECTION": "邮件查看",
  "Close mail inspection": "关闭邮件查看",
  "Folder": "文件夹",
  "All folders": "所有文件夹",
  "Received · Inbox": "已接收 · 收件箱",
  "Read-only inspection. Viewing messages does not change read status.": "只读查看，阅读邮件不会改变已读状态。",
  "No messages in this folder.": "此文件夹中没有邮件。",
  "Choose a message to inspect.": "选择一封邮件查看。",
  "MAILBOX QUOTA": "邮箱配额",
  "Close quota settings": "关闭配额设置",
  "Use the server's default storage quota": "使用服务器默认空间配额",
  "Storage limit": "空间上限",
  "These overrides apply to this account only and take effect immediately.": "这些设置仅影响此账号，并立即生效。",
  "Save quota": "保存配额",
  "Inspect mail": "查看邮件",
  "Storage quota": "空间配额",
  "Loading quota…": "正在读取配额…",
  "{used} used · {messages} messages": "已使用 {used} · 共 {messages} 封邮件",
  "Mailbox quota updated.": "邮箱配额已更新。",
  "Size unit": "容量单位",
  "Invalid size unit": "容量单位无效。",
  "Invalid size": "请输入有效的容量。",
  "Size must be a whole number of bytes": "容量必须对应整数个字节。",
  "Size is outside the allowed range": "容量超出允许范围。",
  "Unable to move message.": "无法移动邮件。",
  "Move the message to Trash before permanently deleting it.": "请先将邮件移入已删除邮件，再将其永久删除。",
  "Unable to save draft. Check your mailbox capacity.": "无法保存草稿，请检查邮箱剩余空间。",
  "Unknown mail folder.": "未知的邮件文件夹。",
  "Account not found.": "找不到此账号。",
  "Invalid account quota.": "账号配额无效。",
  "A quota is required.": "请提供配额。",
  "Administrator mail inspection is read-only.": "管理员邮件查看仅提供只读操作。",
  "Get a certificate from Let's Encrypt": "从 Let's Encrypt 获取证书",
  "Point your domain's DNS to this server and forward public TCP port 80 to PostPlus for HTTP-01 validation.": "将域名 DNS 指向此服务器，并将公网 TCP 80 端口转发至 PostPlus，以完成 HTTP-01 验证。",
  "Start with staging to check your setup. Staging certificates are for testing and are not trusted by browsers or mail clients.": "建议先使用测试环境检查配置。测试证书不受浏览器和邮件客户端信任。",
  "Certificate domain": "证书域名",
  "Certificate contact email": "证书联系邮箱",
  "Certificate environment": "证书环境",
  "Staging · test certificate": "测试环境 · 测试证书",
  "Production · trusted certificate": "正式环境 · 受信任证书",
  "Load certificate authority terms": "获取证书机构条款",
  "Read the certificate authority terms ↗": "阅读证书机构条款 ↗",
  "I have read and agree to the certificate authority terms.": "我已阅读并同意证书机构的服务条款。",
  "Request certificate": "申请证书",
  "Cancel request": "取消申请",
  "Issued certificate file": "签发的证书文件",
  "Issued private key file": "签发的私钥文件",
  "Certificate expires: {date}": "证书到期时间：{date}",
  "Load server settings before applying certificate paths.": "请先加载服务器设置，再应用证书路径。",
  "Use these certificate paths": "使用这些证书路径",
  "The certificate authority returned an invalid terms link.": "证书机构返回了无效的条款链接。",
  "No certificate request is running.": "当前没有进行中的证书申请。",
  "Certificate issued.": "证书已签发。",
  "Certificate request failed.": "证书申请失败。",
  "Certificate request cancelled.": "证书申请已取消。",
  "Certificate request is running. DNS validation can take a few minutes.": "正在申请证书，DNS 验证可能需要几分钟。",
  "Enter a certificate domain and a valid contact email.": "请填写证书域名和有效的联系邮箱。",
  "Starting certificate request…": "正在启动证书申请…",
  "Certificate request queued.": "证书申请已进入队列。",
  "Reading the certificate authority directory.": "正在读取证书机构目录。",
  "Creating an order for the requested domain.": "正在为申请的域名创建订单。",
  "Waiting for domain validation over public HTTP port 80.": "正在等待通过公网 HTTP 80 端口验证域名。",
  "Submitting a signed certificate request.": "正在提交已签名的证书请求。",
  "Downloading and validating the issued certificate chain.": "正在下载并验证签发的证书链。",
  "Could not refresh certificate status. Retrying…": "无法更新证书状态，正在重试…",
  "Cancellation requested. Waiting for the request to stop…": "已请求取消，正在等待申请停止…",
  "Read and accept the current certificate authority terms before requesting a certificate.": "申请证书前，请阅读并同意证书机构当前的服务条款。",
  "The certificate authority terms changed. Load and review the new terms before retrying.": "证书机构条款已变更，请重新获取并阅读条款后重试。",
  "Cannot listen for HTTP-01 validation. Check the challenge port, permissions, and any reverse proxy.": "无法启动 HTTP-01 验证监听，请检查验证端口、权限及反向代理配置。",
  "HTTP-01 domain validation failed. Check public DNS and TCP port 80 reachability.": "HTTP-01 域名验证失败，请检查公网 DNS 和 TCP 80 端口连通性。",
  "The certificate authority rate limit was reached. Wait before trying again; use staging for testing.": "已达到证书机构请求限额，请稍后重试；试验请使用测试环境。",
  "Another certificate request is already running.": "已有其他证书申请正在进行。",
  "Certificate request was not found.": "未找到证书申请。",
  "Could not complete certificate issuance. Check network connectivity, trusted CA roots and certificate directory permissions.": "无法完成证书签发，请检查网络连接、受信任根证书及证书目录权限。",
  "Certificate paths filled. Review and save your configuration.": "已填入证书路径，请检查并保存配置。"
});
  Object.assign(chinese, {
    "Settings":"设置", "Display settings":"显示设置", "Close display settings":"关闭显示设置",
    "These preferences apply to this portal in this browser. Server settings are unchanged.":"这些偏好仅用于此浏览器中的当前界面，不会修改服务器设置。",
    "Appearance":"外观", "Follow system":"跟随系统", "Light":"浅色", "Dark":"深色",
    "Follow system changes appearance when your device switches between light and dark.":"跟随系统会在设备切换深浅模式时自动调整外观。",
    "Layout density":"布局密度", "Comfortable":"舒适", "Compact":"紧凑", "Message text size":"邮件正文字号",
    "Standard":"标准", "Large":"大", "Extra large":"更大", "Check spelling while composing":"写邮件时检查拼写",
    "Changes apply immediately.":"更改立即生效。", "Done":"完成", "Navigation":"导航", "Open navigation":"打开导航", "Close navigation":"关闭导航",
    "Display preferences stay in this browser. The account password policy applies to all accounts.":"显示偏好仅保存在此浏览器中，账户密码策略对所有账户生效。",
    "Display changes apply immediately. Save password policy separately.":"显示更改立即生效，密码策略需单独保存。",
    "Scrollable table":"可滚动表格", "Account password policy":"账户密码策略",
    "Set the requirements for newly created or reset passwords. Existing passwords keep working.":"设置新建或重置密码时的要求，已有密码仍可使用。",
    "Minimum password length":"最小密码长度", "8–128 Unicode characters. The default is 8.":"8 至 128 个 Unicode 字符，默认为 8 个。",
    "Require an uppercase letter (A–Z)":"要求大写字母（A–Z）", "Require a lowercase letter (a–z)":"要求小写字母（a–z）",
    "Require a digit (0–9)":"要求数字（0–9）", "Require a punctuation symbol":"要求标点符号",
    "Letter and digit rules use ASCII characters. Symbols are printable ASCII punctuation; spaces and emoji do not count as symbols.":"字母与数字要求采用 ASCII 字符；符号要求采用可打印的 ASCII 标点，空格和表情不计为符号。",
    "Reload policy":"重新加载策略", "Save password policy":"保存密码策略", "Loading password policy…":"正在读取密码策略…",
    "Could not load the password policy. Close this window and try again.":"无法读取密码策略，请关闭此窗口后重试。",
    "Use at least {count} characters.":"请使用至少 {count} 个字符。", "The password must fit within {count} UTF-8 bytes.":"密码的 UTF-8 编码不能超过 {count} 字节。",
    "Include an uppercase letter (A–Z).":"请包含大写字母（A–Z）。", "Include a lowercase letter (a–z).":"请包含小写字母（a–z）。",
    "Include a digit (0–9).":"请包含数字（0–9）。", "Include a printable ASCII punctuation symbol.":"请包含可打印的 ASCII 标点符号。",
    "Use valid Unicode characters.":"请使用有效的 Unicode 字符。", "The password does not meet the account policy.":"密码不符合账户密码策略。",
    "Choose a minimum length from 8 to 128.":"请选择 8 至 128 之间的最小长度。",
    "Password policy saved. It applies immediately to new and reset passwords.":"密码策略已保存，立即用于新建及重置密码。",
    "The password policy changed. Reload it before saving again.":"密码策略已被修改，请重新加载后再保存。",
    "Check the password policy fields and try again.":"请检查密码策略各字段后重试。"
  });
  Object.assign(chinese, {
    "Could not load the mail domain. Refresh this page and try again.":"无法加载邮箱域名，请刷新页面后重试。",
    "Enter a mailbox name on the displayed domain.":"请输入所显示域名下的邮箱名称。"
  });
  Object.assign(chinese, {
    "Server maintenance": "服务器维护",
    "Back up your data": "备份数据",
    "Create a downloadable archive of mail, accounts, configuration, and saved keys. Keep the archive private: it includes credentials and private mail.": "生成包含邮件、账户、配置和已保存密钥的备份文件供下载。备份含有凭据和私人邮件，请妥善保管。",
    "Create backup": "创建备份",
    "Download backup": "下载备份",
    "Shut down PostPlus": "关闭 PostPlus",
    "Save changes in Server settings and stop all services. Start PostPlus manually from its terminal when you are ready.": "保存服务器设置中的更改并停止所有服务。需要时请在终端手动启动 PostPlus。",
    "Save and shut down": "保存并关闭",
    "Save and shut down the server?": "保存并关闭服务器？",
    "Unsaved changes in Server settings will be saved first. Mail and administration will be unavailable until you start PostPlus again.": "将先保存服务器设置中尚未保存的更改。在重新启动 PostPlus 之前，邮件和管理后台将无法使用。",
    "Account password policy has its own Save button; unsaved policy edits are not included.": "账户密码策略有独立的保存按钮；此操作不会保存尚未保存的密码策略修改。",
    "Creating backup… This may take a few minutes.": "正在创建备份…这可能需要几分钟。",
    "Backup failed. Check service logs and try again.": "备份失败，请检查服务日志后重试。",
    "Backup ready. Download it before the next backup or server restart.": "备份已就绪。请在下一次备份或服务器重启前下载。",
    "Server settings could not be saved. Check the highlighted fields before shutting down.": "服务器设置未能保存。请在关闭服务器前检查标出的字段。",
    "Shutdown requested. Check the terminal for completion. Start PostPlus manually to resume service.": "已请求关闭服务器，请查看终端确认关闭完成。手动启动 PostPlus 即可恢复服务。"
});
  const acmeCodes = {
    terms_required:"Read and accept the current certificate authority terms before requesting a certificate.",
    terms_changed:"The certificate authority terms changed. Load and review the new terms before retrying.",
    http_challenge_bind:"Cannot listen for HTTP-01 validation. Check the challenge port, permissions, and any reverse proxy.",
    challenge_failed:"HTTP-01 domain validation failed. Check public DNS and TCP port 80 reachability.",
    rate_limited:"The certificate authority rate limit was reached. Wait before trying again; use staging for testing.",
    issuance_busy:"Another certificate request is already running.",
    unknown_job:"Certificate request was not found.",
    issuance_failed:"Could not complete certificate issuance. Check network connectivity, trusted CA roots and certificate directory permissions."
  };
  const setupCodes = {port_unavailable:"A service port is unavailable. Choose another port or check permissions.",
    invalid_field:"Check the highlighted fields and try again.", invalid_port:"Ports must be whole numbers from 1 to 65535.", invalid_domain:"Enter a valid mail domain.", invalid_admin:"The administrator address must belong to your mail domain.", weak_password:"Choose a password with at least 8 characters.", invalid_bind:"Enter a valid listen address.", transport_selection_required:"Choose a connection mode.", tls_required:"Network access requires TLS and secure authentication.", invalid_tls:"The TLS certificate or key could not be loaded. Check the server paths and permissions.", invalid_data_dir:"The data folder is invalid or cannot be used. Choose an empty folder.", duplicate_port:"Each service must use a different port.", setup_port_conflict:"A service port conflicts with the setup server.", invalid_environment_name:"Enter a valid environment variable name.", invalid_smarthost_tls:"Choose a valid relay encryption mode. Authentication requires TLS.", invalid_setup_token:"The setup password is incorrect or expired. Copy the latest one-time password from the terminal.", local_access_required:"Setup is only available from this computer.", invalid_origin:"This setup request is not from the setup page. Reopen the launcher URL.", setup_busy:"Setup is already saving. Wait for it to finish.", already_configured:"This server has already been configured.", invalid_json:"The setup request is invalid. Refresh using the launcher URL.", invalid_content_type:"The setup request is invalid. Refresh using the launcher URL.", provision_failed:"Could not create the server data or administrator. Check the launcher output and folder permissions.", config_commit_failed:"Could not save the configuration file. Check the launcher output and file permissions.", setup_failed:"Setup failed. Check the launcher output before trying again."
  };
  const languageKey = window.PostPlusPreferences?.key("language") || "postplus.language";
  let language = "en";
  try { if ((localStorage.getItem(languageKey) ?? localStorage.getItem("postplus.language")) === "zh-CN") language = "zh-CN"; } catch { /* Storage can be disabled. */ }
  function t(key, parameters = {}) {
    const source = language === "zh-CN" ? (chinese[key] || key) : key;
    return source.replace(/\{(\w+)\}/g, (match, name) => Object.hasOwn(parameters, name) ? String(parameters[name]) : match);
  }
  function apply(root = document) {
    root.querySelectorAll("[data-i18n]").forEach(node => {
      if (!node.dataset.i18n) node.dataset.i18n = node.textContent.trim();
      node.textContent = t(node.dataset.i18n);
    });
    for (const attribute of ["aria-label", "title", "placeholder"]) {
      root.querySelectorAll(`[data-i18n-${attribute}]`).forEach(node => node.setAttribute(attribute, t(node.getAttribute(`data-i18n-${attribute}`))));
    }
    document.documentElement.lang = language;
    document.querySelectorAll("[data-language]").forEach(select => { select.value = language; });
  }
  function error(data) {
    if(data?.code==="password_policy_conflict")return t("The password policy changed. Reload it before saving again.");
    if(data?.code==="invalid_password_policy")return t("Check the password policy fields and try again.");
    if (acmeCodes[data?.code]) return t(acmeCodes[data.code]);
    if (setupCodes[data?.code]) return t(setupCodes[data.code]);
    const message = data?.error || "";
    if (Object.hasOwn(chinese, message)) return t(message);
    for (const [prefix, key, parameter] of [["Missing text field: ", "Missing text field: {field}", "field"], ["Field is too long: ", "Field is too long: {field}", "field"], ["A local recipient account does not exist: ", "A local recipient account does not exist: {recipient}", "recipient"]]) {
      if (message.startsWith(prefix)) return t(key, {[parameter]: message.slice(prefix.length)});
    }
    if (data?.code === "invalid_configuration" && data.field) return t("Check the configuration field: {field}.", {field:data.field});
    return t("The request failed. Please try again.");
  }
  apply();
  function setLanguage(value, persist = true) {
    language = value === "zh-CN" ? "zh-CN" : "en";
    if(persist) try { localStorage.setItem(languageKey, language); } catch { /* Language still works for this page. */ }
    apply();
    document.dispatchEvent(new CustomEvent("postplus:language"));
  }
  document.querySelectorAll("[data-language]").forEach(select => select.addEventListener("change", () => setLanguage(select.value)));
  return {t, apply, error, setLanguage, get language() { return language; }};
})();
