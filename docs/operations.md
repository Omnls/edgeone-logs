# 运维文档：EdgeOne 实时 HTTP 日志接收器

本文档覆盖运行时配置、EdgeOne 控制台配置、522/回源排查方法与已知边界。文中严格区分「官方文档已确认」与「本项目自设」两类限制，并单列尚未验证的事项。

## 1. 环境变量

| 变量 | 用途 | 缺失时行为 |
| --- | --- | --- |
| INGEST_SHARED_KEY | 独立接收密钥，投递方在请求头 X-Ingest-Key 中携带 | 返回 503 ingest_key_not_configured，不放行 |
| ADMIN_SHARED_KEY | 管理查询密钥，请求头 X-Admin-Key | 返回 503 admin_key_not_configured，不放行 |
| EDGEONE_LOG_SECRET_ID | 控制台「加密签名」中的 SecretId（即 access_key） | 与 SecretKey 同时缺失表示签名层未启用 |
| EDGEONE_LOG_SECRET_KEY | 控制台「加密签名」中的 SecretKey，官方要求固定 32 位 | 同上；只配其中一个返回 503 signature_config_invalid |
| BLOB_STORE | Pages Blob store 名称 | 使用默认名 edgeone-realtime-logs |

两类密钥互不通用：接收密钥不能查询日志，管理密钥不能投递日志。

### 签名强制策略

是否强制校验官方签名由**部署配置**决定，不由「请求里有没有签名参数」决定：

- SecretId 与 SecretKey 都配置好：每次投递都必须带合法 auth_key/access_key。去掉 query 参数不能降级绕过，一律 401。
- 只配置一个：配置不完整，返回 503，不猜测意图。
- 都不配置：签名层未启用，仅由 X-Ingest-Key 把关；此时若请求仍带签名参数，因无法验证而返回 401。

签名算法为 md5(uri-timestamp-rand-SecretKey)，见 docs/reference/61296.md:153。**官方文档的计算示例哈希值有误**：文档给出 1f7ffa7bff8f06bbfbe2ace0f14b7e16，而 md5("/access_log/post-1571587200-0-YourKey") 的真实值是 d8079ca27f0db9157de64061e7264b8e（已本地复算并写入 tests/auth.test.js）。文档示例的最终 URL 路径 /cdnlog/post 也与其 uri 参数 /access_log/post 不一致；实现按真实请求路径计算。

## 2. EdgeOne 控制台配置

1. 实时日志推送中新建任务，目的地选择 **HTTP 服务（POST）**。
2. 接口地址填部署后的 https://<域名>/edgeone-logs。
3. 日志输出格式保持默认 **JSON Lines**（docs/reference/64485.md）。CSV 与自定义模板格式本接收器不支持，会返回 400。
4. 内容压缩可勾选 gzip；EdgeOne 会带上 Content-Encoding: gzip，接收端按该头解压。
5. 源站鉴权选择「加密签名」时填入 SecretId/SecretKey，与环境变量保持一致。
6. **自定义 HTTP 请求头**添加 X-Ingest-Key，取值为 INGEST_SHARED_KEY。官方明确支持自定义请求头（docs/reference/61296.md:34），因此这层鉴权有官方配置依据。
7. 保存时控制台会发起一次连通性校验，正文是多行缩进的**单个 JSON 对象**（61296.md:39-64），本接收器按完整 JSON 文档优先解析，能正确识别。
8. 可选：控制台侧筛选 SecurityAction、SecurityModule、EdgeResponseStatusCode、OriginResponseStatusCode（61297.md）削减推送量。接收端不假设上游已过滤。

### 日志回环

接收器自身的域名不要作为同一个推送任务的日志来源，否则每次投递都会产生新的访问日志再次触发投递，形成放大回环。若接收器与被观测站点在同一站点下，请在推送任务的域名范围中排除接收器域名。

## 3. 时间与分区语义

官方预设时间字段 RequestTime、LogTime、EdgeEndTime 均为 **Timestamp ISO8601**（61300.md:24,26,60，如 2024-10-14T05:13:43Z），不是秒级整数。签名参数里的 timestamp 才是 10 位秒级时间戳，两者格式不同，不要混用。

分区时间只来自记录自身的时间字段，从不使用当前时间。一次投递若跨越 UTC 小时边界，会按记录各自的小时拆成多个批次分别落到 logs/<date>/<hour>/ 下，而不是整批塞进第一条记录所在的小时。批次键由规范化后的记录内容的 SHA-256 派生：对象键递归排序、嵌套数组顺序保留、内容重复的记录不去重，因此同一批内容即使记录顺序或字段顺序不同，也会得到同一个键。

条件写冲突不直接判为 duplicate。此时会以 consistency:'strong' 读回已存在的对象，逐项核对 schemaVersion、recordCount 以及重新计算的 records 摘要，三项全部一致才返回 duplicate 并确认接收。读回失败、对象缺失、schema 不符或摘要不一致一律抛错并返回 5xx，绝不在内容未经证实一致的情况下确认接收。

**不使用 RequestID 集合作为批次身份**：官方说明长连接（WebSocket）会对同一 RequestID 周期性输出多条日志，RequestID 集合相同但内容不同的两批日志会被误判为重复而丢弃。

## 4. 确认与错误语义

任一非空行或数组元素不是合法 JSON 对象，整批返回 400 且**零写入**，不做「跳过坏行后确认」。这样投递方重投的是完整批次，不会静默丢记录。

| 状态 | 含义 |
| --- | --- |
| 200 | 已确认接收（含幂等重复），返回 result_code、result_desc、timestamp 与写入统计 |
| 400 | 正文不可用：empty_body、invalid_record、unsupported_body、gzip_failed、missing_record_timestamp |
| 401 | 鉴权失败（统一使用 401，实现中不存在 403 路径） |
| 405 | 方法不允许，带 Allow 响应头 |
| 413 | 超出体积上限：payload_too_large、record_too_large、batch_too_large、too_many_records、record_too_deep、too_many_partitions、too_many_chunks |
| 415 | Content-Encoding 不被支持：未知编码（br、deflate 等）或叠加编码（gzip, gzip）。只接受空/identity 与单一 gzip |
| 500 | 存储异常或内容一致性无法证实，投递方应重投；重投时内容相同的分组经读回校验后确认为 duplicate，不会重复存储 |
| 503 | 部署配置缺失或不完整 |

错误响应只含固定分类码，不含异常堆栈、日志正文片段、行内容、query 串或凭据。所有响应（含错误）都带 Cache-Control: no-store、Content-Type: application/json; charset=utf-8、X-Content-Type-Options: nosniff、Referrer-Policy: no-referrer。

## 5. 脱敏规则

默认脱敏在写入前执行，递归处理嵌套结构（最大深度 32）。达到深度上限的子树不会原样放行，而是整体替换为 [TRUNCATED_DEPTH]，避免深层嵌套成为凭据的绕过路径；循环引用同样替换为该占位符。

规则如下：

- 凭据类字段名（Authorization、Cookie/Set-Cookie、各类 Token/ApiKey/Secret/Password/Credential/PrivateKey，以及包含这些子串的未知字段名如 X-Custom-Auth-Token）整体替换为 [REDACTED]，不保留内部结构。
- 请求正文类字段（body、RequestBody、payload 等）同样替换。
- RequestUrlQueryString 默认整体移除为 [REMOVED]，只保留「有/无」信号。原值为 - 或空串时原样保留。
- URL 形态字段（RequestUrl、RequestReferer、Location，以及以 url/uri 结尾的字段）移除 userinfo、query 与 fragment，保留 scheme/host/path。

**保留不动**的排查信息：EdgeResponseStatusCode、OriginResponseStatusCode、全部 Origin* 诊断字段、EdgeException（按原值保留，不做枚举白名单，未来新增取值不会被丢弃）、RequestID、RequestHost、RequestMethod、ClientIP、各类耗时字段。无明显敏感性的未知诊断字段一并保留。

## 6. 522 / 回源排查

诊断信号（61300.md）：

- EdgeException：格式为 client_request_exception 或 edge_response_exception 加异常描述，无异常为 no_exception。回源相关高频取值：timeout（522 典型直接原因）、upstream_failed、domain_resolve_failed、domain_resolve_none、upstream_server_is_empty、peer_close、peer_error、upstream_status_change。
- OriginResponseStatusCode：源站实际状态码；-1 表示本次未回源。
- OriginIP、OriginDomain：实际连接的源站，确认是否为预期目标。
- OriginTCPHandshakeDuration、OriginTLSHandshakeDuration、OriginDNSResponseDuration、OriginResponseHeaderDuration：分阶段耗时。-1 表示无值；连接复用时可能为 0，**不代表异常**。
- EdgeResponseStatusCode、EdgeResponseTime、EdgeInternalTime：区分边缘侧问题与回源问题。

查询步骤：

1. 确定问题发生的 UTC 日期与小时。date 与 hour 必须成对提供，都不提供则默认查当前 UTC 小时。
2. GET /logs-admin?date=2026-09-13&hour=02&status=522，或用 statusMin/statusMax 查范围。状态码筛选同时比对 EdgeResponseStatusCode 与 OriginResponseStatusCode，只看边缘码会漏掉回源侧证据。
3. 检查命中记录的 EdgeException 与 Origin* 字段，判断失败发生在哪个阶段。
4. OriginResponseStatusCode 不为 -1 说明确实连上了源站并收到响应，问题更可能在源站自身返回的状态码。

这套路径不限于 522：任何 4xx/5xx 或 EdgeException 不等于 no_exception 的请求都用同样字段与同样查询方式定位。

## 7. 限制边界

### 官方文档已确认

来源 https://pages.edgeone.ai/document/limits-and-quotas 与本地 SDK 实现：

- Cloud Functions 请求体与响应体各 6 MB。
- 含依赖的代码包 128 MB。
- 默认执行 30 秒，最高可配 120 秒。
- Pages Blob 键长最大 600 字节（SDK 内部校验，见 node_modules/@edgeone/pages-blob/dist/index.js）。
- store 名：非空，不含斜杠与冒号，仅字母数字下划线连字符，最长 64 字节。

### 本项目自设（非平台限制）

- 接收端原始正文上限 4 MiB。注意平台限制是 6 MB（十进制）而不是 6 MiB，两者不等；这里取 4 MiB 留出余量，超限在读流过程中即中断并返回 413，不依赖 Content-Length。
- 单批次序列化上限 4 MiB、单批次记录数上限 5000 条。超限时按内容顺序切分为稳定子批次，不截断、不丢记录；单条记录本身超限返回 413 record_too_large。
- 单次投递最多 24 个小时分区、每个分区最多 32 个子批次，超出返回 413。避免一次请求产生无界数量的存储写入。
- gzip 解压后上限 16 MiB，防解压炸弹；单次投递记录总数上限 5000 条，单条记录嵌套深度上限 32 层，均在递归处理之前校验。
- 生成的批次键形如 logs/2026-09-13/02/<64 位十六进制>.json，长度远低于 600 字节上限。
- 管理查询默认扫描 5 个批次，硬上限 10 个；累计读取字节预算 16 MiB（未匹配的批次同样计入，因为 SDK 会把整个对象缓冲进内存），响应字节预算 5 MiB，任一超出返回 413 要求缩小范围，不静默截断。
- 生产环境建议独立密钥至少 24 字符（仅建议，不改变判定结果）。接收端与管理端密钥配置为相同值时失败关闭，两种权限不可互换。

## 8. 容量管理

**本项目未实现日志过期自动清理**，也不在运行时执行任何 Blob 删除。已写入的批次会一直保留，长期运行对象数量持续增长。

人工清理方式：批次键按 logs/<UTC 日期>/<UTC 小时>/ 分区，可按日期前缀列举并删除超过保留期的对象。删除属于不可逆操作，需单独授权后执行，本项目代码不提供删除入口。建议按站点流量估算日增量后确定保留期，并定期检查项目存储配额。

## 9. 尚未验证的事项

以下为诚实标注的未验证项，均需在真实 Pages 环境中确认：

- **真实部署与真实 Blob 写入未验证**。全部测试运行在离线环境，使用内存中的存储替身而非真实 @edgeone/pages-blob 传输层。getStore(name) 在 Pages Functions 内自动鉴权这一点来自官方文档与 SDK 类型定义，但本项目未在真实运行时中执行过它；离线环境下 SDK 会因缺少部署凭据抛 MISSING_ENVIRONMENT。
- **未接入真实 EdgeOne 推送流量**，未做端到端连通性测试。
- **未实现速率限制**。接收端与管理端在通过鉴权的前提下可被高频调用。
- 管理查询**不支持跨分区自动扫描**：一次查询只覆盖一个 UTC 日期加小时分区。跨多小时排查需分别查询后自行合并。这是当前实现的边界。
