# EdgeOne 实时日志接收器

把腾讯 EdgeOne 七层访问日志通过「实时日志 → HTTP 服务（POST）」推送到本项目，
落盘到 EdgeOne Pages Blob，用于排查 522 及其他 HTTP 错误。

## 运行要求

- Node.js 20 及以上（`edgeone.json` 中 `nodeVersion` 为 20.18.0）。
- 一个 EdgeOne Pages 项目，已启用 Pages Blob 存储。

## 安装与本地检查

```bash
npm install --ignore-scripts --no-audit --no-fund
npm run check      # 语法检查 + 单元测试
```

`npm run check` 等价于 `node scripts/check-syntax.mjs` 加 `node --test "tests/**/*.test.js"`。
全部测试都在离线存储替身上运行，不连真实 Blob。

## Pages 控制台构建设置

在 EdgeOne Pages 创建项目并绑定本仓库时，构建设置按以下填写：

| 字段 | 填写值 | 说明 |
| --- | --- | --- |
| 框架预设 | `Other` | 本项目没有前端框架，函数由平台按 `edgeone.json` 直接打包。 |
| 根目录 | `./` | 保持默认。 |
| 输出目录 | `public` | 唯一的静态输出目录，只有一个占位页 `public/index.html`。 |
| 构建命令 | 留空 | 没有构建步骤；若控制台要求非空，可填 `echo skip`。 |
| 安装命令 | `npm install` | 安装唯一依赖 `@edgeone/pages-blob`，Cloud Functions 运行时需要。 |

环境变量按下方「环境变量」一节填写，至少要配置 `INGEST_SHARED_KEY` 与
`ADMIN_SHARED_KEY`，两者都建议用高强度随机字符串，例如：

```bash
openssl rand -hex 32
```

## 目录结构

```
cloud-functions/
  edgeone-logs.js               POST /edgeone-logs        日志接收入口
  logs-admin/index.js           GET  /logs-admin          管理查询入口
  logs-admin-login/index.js     POST /logs-admin-login    管理端登录，签发会话 Cookie
  logs-admin-logout/index.js    POST /logs-admin-logout   管理端登出，清除会话 Cookie
server/
  lib/auth.js               EdgeOne 签名算法 + 固定时间密钥比较
  lib/session.js            会话 token 签发与校验（无服务器侧状态）
  lib/login-rate-limit.js   登录失败尽力而为限流
  lib/parse-log-body.js     gzip 解压与 JSON Lines / 单对象 / 数组解析
  lib/redact.js             默认脱敏规则
  lib/http.js               统一响应头（no-store、nosniff）
  routes/ingest.js          接收端业务逻辑
  routes/admin.js           查询端业务逻辑
  routes/admin-login.js     登录端业务逻辑
  storage/batch-store.js    批次键计算与幂等写入
  storage/get-store.js      生产环境唯一的 getStore 入口
public/index.html          输出目录占位页
public/admin.html           零依赖管理查询页面（登录 + 查询 + 登出）
```

函数目录固定为 `cloud-functions/`，默认导出 `onRequest(context)`，文件名决定路由路径
（依据 https://pages.edgeone.ai/document/node-functions ）。

## 环境变量

复制 `.env.example` 并在 Pages 控制台配置同名变量。

| 变量 | 必填 | 说明 |
| --- | --- | --- |
| `INGEST_SHARED_KEY` | 是 | 接收端独立密钥。缺失时接收端返回 503，不会放行。建议至少 24 字符。 |
| `ADMIN_SHARED_KEY` | 是 | 管理查询密钥。必须与接收端密钥不同，两者不可互换。 |
| `BLOB_STORE` | 否 | Blob store 名，默认 `edgeone-realtime-logs`。只允许字母数字下划线连字符，最长 64 字节。 |
| `EDGEONE_LOG_SECRET_ID` | 否 | 控制台「加密签名」的 SecretId。 |
| `EDGEONE_LOG_SECRET_KEY` | 否 | 控制台「加密签名」的 SecretKey，官方要求固定 32 字符。 |

签名两个变量必须同时配置或同时留空。只配置一个时接收端返回 503，不猜测意图。
两个都配置后，每次投递都必须带合法签名，去掉 query 参数不能降级绕过。

## 控制台配置

在 EdgeOne 控制台创建实时日志推送任务（参考 docs/reference/61296.md）：

1. 数据源选七层访问日志，勾选需要的字段。排查 522 时至少保留
   `RequestTime`、`RequestID`、`RequestHost`、`RequestUrl`、`EdgeResponseStatusCode`、
   `OriginResponseStatusCode`、`EdgeException`、`ClientIP`。
2. 日志输出格式保持默认的 **JSON Lines**。本项目也接受单个 JSON 对象与 JSON 数组，
   但不支持 CSV 与自定义模板格式，收到时会明确返回 400。
3. 目的地选 **HTTP 服务（POST）**，接口地址填 `https://<你的域名>/edgeone-logs`。
4. 内容压缩若控制台支持可勾选 gzip，接收端按 `Content-Encoding: gzip` 解压；
   若该推送任务的控制台界面没有提供 gzip 选项（部分账号/版本不支持），
   直接留空即可，接收端同样接受未压缩的 JSON Lines 正文。
5. 自定义 HTTP 请求头添加 `X-Ingest-Key: <INGEST_SHARED_KEY 的值>`。
6. 源站鉴权如需更强校验，选加密签名并填入与环境变量一致的 SecretId / SecretKey。

配置阶段控制台会先发一条连通性校验请求，正文是多行缩进的单个 JSON 对象。
这条请求同样需要带 `X-Ingest-Key`，否则会被 401 拒绝。

## 查询日志

### 方式一：Web 管理页面

访问 `https://<你的域名>/admin.html`，输入 `ADMIN_SHARED_KEY` 登录。登录成功后
浏览器会收到一个 `HttpOnly; Secure; SameSite=Strict` 的会话 Cookie（有效期 12
小时），页面本身不读取、不缓存该 Cookie 或密钥。之后可在页面上按日期/小时/
状态码/host/requestId 过滤查询、翻页，点击「退出登录」清除会话。

### 方式二：命令行 + 请求头

```bash
curl -H "X-Admin-Key: $ADMIN_SHARED_KEY" \
  "https://<你的域名>/logs-admin?date=2026-09-13&hour=02&statusMin=500&statusMax=599"
```

参数：`date` 与 `hour` 必须成对出现（UTC），都不传则默认查询当前 UTC 小时；
`status` 精确匹配单个状态码，`statusMin`/`statusMax` 匹配范围，两者互斥；
`host`、`requestId` 精确匹配；`limit` 为本页扫描的批次数，范围 1..10，默认 5；
`cursor` 用于翻页。状态码同时比对 `EdgeResponseStatusCode` 与
`OriginResponseStatusCode`，避免漏掉回源侧的 522 证据。

返回中的 `scannedBatches`、`matchedRecords` 只描述当前这一页，不是分区全量统计。
响应字节超过 5 MiB 预算时返回 413 要求缩小范围，不会静默截断。

`/logs-admin` 同时接受 `X-Admin-Key` 请求头与登录后签发的会话 Cookie，任一通过
即可，两种方式可以并存使用。

### 登录 / 登出接口

```bash
# 登录：成功返回 200 并在响应头带 Set-Cookie
curl -i -X POST -H "content-type: application/json" \
  -d '{"adminKey":"'"$ADMIN_SHARED_KEY"'"}' \
  "https://<你的域名>/logs-admin-login"

# 登出：清除会话 Cookie，不需要携带任何凭据
curl -i -X POST "https://<你的域名>/logs-admin-logout"
```

会话 token 是无状态的：仅由 `ADMIN_SHARED_KEY` 签名的 `{ exp }` 时间戳构成，
服务端不持久化任何会话记录，登出只是让浏览器丢弃本地 Cookie。登录失败按 UTC
小时分桶计数，同一小时内失败次数达到上限（10 次）后直接返回 429，不再进行
密钥比较；该限流是尽力而为的附加保护，非强一致，也不会因为限流子系统本身
故障而拖累正常登录（见 `server/lib/login-rate-limit.js` 顶部注释）。

## 522 排查思路

522 是回源连接超时。先按 `statusMin=522&statusMax=522` 或 `status=522` 拉出记录，
再看 `OriginResponseStatusCode` 与 `EdgeException`：前者为空或异常说明源站没有正常应答，
后者携带 EdgeOne 侧的异常分类。配合 `RequestHost`、`RequestUrl`、`RequestTime`
定位是否集中在某个域名、路径或时间段。

## 日志回环

不要把接收器自己的域名配置成同一个推送任务的日志源。接收日志的请求本身会产生访问日志，
再被推回接收器，形成放大回环。给接收器单独用一个域名，或在日志源里排除该域名。

## 已知边界

平台事实（来自官方文档，非本项目设定）：

- 请求体与响应体各 6 MB，代码包含依赖 128 MB，默认超时 30 秒、最高 120 秒
  （https://pages.edgeone.ai/document/limits-and-quotas ）。注意 6 MB 不等于 6 MiB。
- Blob 键最长 600 字节（SDK 内部校验），本项目生成的键远低于该值。

本项目自设上限（可按需调整，都不是平台限制）：

- 接收端原始正文 4 MiB。取值低于平台的 6 MB，留出余量。读取时边读边累计，
  超限立即取消上游流，不依赖 `Content-Length`。
- gzip 解压后 16 MiB；单次投递最多 5000 条记录；单条记录嵌套最深 32 层。
  三项都在递归处理之前校验，超限返回 413。
- 单批次序列化 4 MiB、5000 条。跨 UTC 小时的一次投递按记录各自的小时拆成多个批次，
  单个小时内超限则按内容顺序切分为稳定子批次；单次投递最多 24 个小时分区、
  32 个子批次。所有校验在任何写入之前完成，任一项不通过则零写入。
  单条记录本身超限时返回 413，不截断、不丢弃。
- 脱敏递归最深 32 层，超出深度的子树替换为 `[TRUNCATED_DEPTH]` 占位符，
  不原样放行（原样放行可能漏掉深层凭据）。
- 管理查询累计读取预算 16 MiB、响应字节预算 5 MiB，超出返回 413 要求缩小范围。
- **没有实现自动过期清理**。日志会一直留在 Blob 里占用配额，需要人工按
  `logs/<UTC 日期>/<小时>/` 前缀定期删除。本项目不执行删除操作。
- 真实 Pages 部署与真实 Blob 读写尚未验证，见 docs/operations.md 的未验证项一节。
