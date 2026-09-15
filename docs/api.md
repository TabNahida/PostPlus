# Web / 管理 API v1

所有 JSON 请求使用 `Content-Type: application/json`。API 与 Webmail 同源。证书配置后整个 Web 监听器使用 HTTPS。没有注册 API。

## 会话

`POST /api/login`：`{"username":"user@localhost","password":"..."}`，返回 `ok, username, admin, csrf, expires_in`，并设置 `pp_session` Cookie。后续请求携带 Cookie；除登录之外的写请求还必须携带 `X-CSRF-Token: <csrf>`。

`GET /api/session` 返回当前账户和 CSRF 令牌。`POST /api/logout` 撤销当前会话并清除 Cookie。Cookie 是 HttpOnly、SameSite=Strict；HTTPS 下附加 Secure。会话保存在 Web 进程内存，默认一小时，重启后失效。

## 邮箱

| 方法/路径 | 请求/响应 |
| --- | --- |
| GET `/api/messages` | 当前用户邮箱；`messages` 含 id、uid、size、seen、internal_date；最新 100 封附带可选 subject/from/date 摘要 |
| GET `/api/messages/{id}` | `raw` 原文显示文本及 `message` 解码后的 subject/from/to/date/text；标记已读 |
| DELETE `/api/messages/{id}` | 删除当前用户邮件 |
| POST `/api/send` | `{"to":["friend@localhost"],"subject":"Hello","text":"内容"}`；成功入队返回 202 |

原始邮件的二进制精确保留由存储和邮件协议保证；Web JSON 中不能表示的非 UTF-8 字节按替换字符显示。当前不提供二进制附件下载或 HTML 渲染。读取邮件可能更新 Seen，API 不应被用作无副作用的预取接口。

## 管理员

| 方法/路径 | 请求/响应 |
| --- | --- |
| GET `/api/admin/users` | 用户名、管理员标志；不返回密码材料 |
| POST `/api/admin/users` | username、password、admin；必须是配置域名中的地址 |
| POST `/api/admin/password` | username、password；撤销该用户的 Web 内存会话 |
| GET `/api/admin/stats` | messages、bytes、queued、queued_bytes、quarantined |
| GET `/api/admin/queue` | 最多 100 个队列条目、状态、错误；不返回原文 |

普通账户访问管理路由返回 403。CLI 修改密码不会向 Web 进程推送撤销通知，已有 Web 会话到 TTL 才失效；需要立即全部撤销时重启 Web 进程。

常见状态码：400 输入错误、401 未登录/认证失败、403 角色或 CSRF/传输限制、404 不存在、409 重复账户、413 超大小、429 限流、503 依赖不可用。`GET /health` 仅反映 Web 进程活跃，不代表其他进程或 ClamAV 健康。
