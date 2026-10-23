# Banner 指纹识别系统（Go + Docker Compose）

批量接收网络扫描原始数据（`ip` / `port` / `banner`），识别协议、产品、版本与 OS 线索，
输出带置信度的结构化指纹。**client + server 双程序，`docker compose up` 一键起。**

```text
$ docker compose up --build
server-1  | {"level":"INFO","msg":"banner fingerprint server started","version":"1.0.0","addr":"[::]:8080",
             "rules_source":"embedded","rules_version":"2026.10.23","probes":16,"os_hints":19}
server-1  | {"level":"INFO","msg":"http","method":"GET","path":"/health","status":200,...}
client-1  | #   IP        PORT   PROTOCOL  PRODUCT        VERSION  OS_HINT  CONF  BANNER
client-1  | 1   1.2.3.4   22     SSH       OpenSSH        8.9p1    Ubuntu   0.97  SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
client-1  | 2   1.2.3.5   80     HTTP      nginx          1.24.0            0.92  HTTP/1.1 200 OK\r\nServer: nginx/1.24.0...
client-1  | 3   1.2.3.6   443    HTTP      Apache         2.4.57            0.92  HTTP/1.1 200 OK\r\nServer: Apache/2.4.57
client-1  | 4   1.2.3.7   3306   MySQL     MySQL          8.0.32            0.94  J\x00\x00\x00\n8.0.32\x00
client-1  | 5   1.2.3.8   6379   Redis     Redis                            0.70  -ERR wrong number of arguments...
client-1  | 6   1.2.3.9   21     FTP       ProFTPD        1.3.7             0.92  220 ProFTPD 1.3.7 Server (ProFTPD)
client-1  | 7   1.2.3.10  8080   HTTP      Jetty          9.4.51            0.92  HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51
client-1  | ...
client-1  | 20  1.2.3.23  12345  unknown                                    0.10  QUIT
client-1  | total=20 identified=19 unknown=1 avg_confidence=0.85
```

自测数据 20/20 全部按预期识别（含 1 条**必须**判为 `unknown` 的负样本），
`go test ./...` 把它固化成了 golden test。

---

## 1. 快速开始

```bash
docker compose up --build        # 起 server + 跑一遍 client，client 打印结果后退出
docker compose down              # 停止
```

- 默认**不发布任何宿主机端口**，client 通过 compose DNS 用 `http://server:8080` 访问 server。
- `client` 是一次性 Job：`depends_on: {server: {condition: service_healthy}}`，服务没真正健康就不会发请求。
- 想从宿主机调接口（调试用，显式例外）：

```bash
docker compose -f docker-compose.yml -f docker-compose.debug.yml up --build -d server
curl -s localhost:8080/health
curl -s -X POST localhost:8080/fingerprint -d @examples/input.json
```

- 换数据：把文件挂到 client 的 `/data/input.json`，或直接跑 client 镜像：

```bash
docker compose run --rm -v "$PWD/examples:/data:ro" client -input /data/input_edge.json -json
```

本地开发（不用容器）：

```bash
go test ./...
go run ./cmd/server -addr :8080 &
go run ./cmd/client -input examples/input.json -server http://127.0.0.1:8080
```

---

## 2. 架构与数据流

```text
             ┌──────────────────────────────┐
 examples/   │ client  (cmd/client)         │
 input.json ─▶ 读文件 → 解析 → 分批 → POST  │
   (只读挂载) │ → 表格 / JSON 展示 → 退出     │
             └───────────────┬──────────────┘
                             │ HTTP  POST /fingerprint
                             │ http://server:8080（compose DNS，无宿主端口）
             ┌───────────────▼──────────────┐
             │ server  (cmd/server)         │
             │  api ─▶ pipeline ─▶ engine   │
             │                       │      │
             │             rules/*.json     │  ← go:embed（或 -rules-dir 覆盖）
             └──────────────────────────────┘
```

单条 banner 的识别流水线（纯内存、无外部依赖）：

```text
raw banner
  │ ① banner.Decode    转义归一化（\xNN / \uNNNN / 裸控制字节 → 精确字节序列）+ ASCII 小写视图 + 截断
  ▼
  │ ② engine.classify  每个 probe 独立打分（all/any/none 证据），取最高分协议；低于阈值 → unknown
  ▼
  │ ③ engine.extract   在胜出协议作用域内按规则顺序抽产品名与版本号（捕获组模板）
  ▼
  │ ④ engine.score     base + 产品权重 + 版本命中 + OS 线索 + 端口一致性 → clamp(0, 0.99)
  ▼
Result{ip, port, protocol, product, version, os_hint, confidence}
```

无状态、无 DB、无外部服务 —— 这也是运行镜像能做到 `scratch` + `read_only` 的前提。

---

## 3. 目录结构

| 路径 | 职责 |
|---|---|
| `cmd/server` | 服务端 main：装配规则/引擎/HTTP，含 `-healthcheck` 自探活模式、优雅退出 |
| `cmd/client` | 客户端 main：读文件、分批调用、重试、展示 |
| `internal/model` | **契约层**：输入/输出结构、字段别名与宽松解析、非严格 JSON 修复 |
| `internal/banner` | **归一化层**：转义还原、二进制安全的小写视图、截断 |
| `internal/engine` | **识别层**：规则编译 + 打分 + 字段抽取 + unknown 兜底 |
| `internal/pipeline` | **编排层**：并发保序、单条 panic 隔离（进 N 条必出 N 条） |
| `internal/api` | **接入层**：路由、请求校验、4xx/5xx 语义、recover、访问日志 |
| `internal/report` | 展示层：对齐表格 / JSON / 汇总 |
| `internal/obs` | 结构化日志（JSON → stdout） |
| `rules/` | **规则数据 + 加载器（go:embed）**：`protocols.json`、`os.json` |
| `examples/` | 自测数据与 golden 期望：`input.json`、`input_edge.json`、`expected.json` |
| `Dockerfile` | 单文件多 target（`server` / `client`），两阶段构建 → scratch |
| `docker-compose.yml` | 一键启动 + 安全加固；`docker-compose.debug.yml` 为调试例外 |

---

## 4. HTTP 接口

### `POST /fingerprint`

请求：JSON 数组（也兼容 `{"items":[...]}` / 单个对象 / NDJSON，见 §7.2）

```json
[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}]
```

响应 `200`：与输入**等长、同序**的数组，每条固定 7 个字段（缺失值为 `""`，不是 `null`）

```json
[{"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1",
  "os_hint":"Ubuntu","confidence":0.97}]
```

失败语义：

| 情况 | 状态码 | 说明 |
|---|---|---|
| 单条字段缺失/类型不对/空 banner | `200` | 该条回落 `unknown`，其余照常，**不报错** |
| 整个 body 不是可解析的 JSON | `400` | `{"error":"invalid_body","detail":"..."}` |
| 批量条数超过上限（默认 20000） | `413` | `{"error":"batch_too_large",...}` |
| 请求体超过 32MB | `413` | `{"error":"body_too_large",...}` |
| 服务端内部 panic | `500` | recover 后返回，进程不退出 |

### `GET /health`

```json
{"status":"ok","service":"banner-fingerprint","version":"1.0.0","rules_version":"2026.10.23",
 "probes":16,"os_hints":19,"uptime_seconds":12,"stats":{"requests":2,"items":33,"unknown":4}}
```

返回 `probes` 数量是刻意设计：**一眼确认规则真的加载了**，而不是只回一个 `{"status":"ok"}`。

### `GET /version`

构建版本、规则版本、规则文件清单、probe 数量。

---

## 5. 识别能力

必达标的全在，另外顺带覆盖了常见协议（全部靠规则文件扩展，没有为它们写代码）：

| 协议 | 产品/版本抽取 | 判定证据 |
|---|---|---|
| SSH | OpenSSH、Win32-OpenSSH、Dropbear、libssh、Cisco、RomSShell | `SSH-2.0-<software>` 识别串 |
| HTTP | nginx、Apache、Jetty、Microsoft-IIS、Tomcat、OpenResty、gunicorn、Werkzeug、Envoy、Caddy、Cloudflare、LiteSpeed、Kestrel | 响应行 + `Server` 头（**与端口无关**） |
| MySQL | MySQL（版本来自握手包）、MariaDB | 二进制握手结构：3B 长度 + 序号 + `0x0a` + NUL 结尾版本 |
| Redis | Redis（版本来自 `redis_version:`，通常无） | RESP 状态/错误/批量/整数行 |
| FTP | ProFTPD、vsftpd、Pure-FTPd、FileZilla Server、Serv-U、wu-ftpd、Microsoft FTP | `220/120` 欢迎行 + 负样本抑制 |
| TLS | —（握手包不含产品信息） | record 头 `0x16/0x15/0x17` + 版本 `0x0300-0x0304` |
| SMTP / POP3 / IMAP | Postfix、Exim、Sendmail、Exchange、Dovecot、Cyrus… | 欢迎行 + 关键字互斥（220/+OK 的歧义靠 none/all 消解） |
| Memcached / MongoDB / Elasticsearch / PostgreSQL / VNC / Telnet / SMB | 视协议而定 | 文本命令回显、JSON 字段、协议魔术字 |
| 其他 | `unknown`（confidence 0.00~0.10） | 无有效证据时不猜 |

**命名规范化约定**：产品名使用项目官方写法（`nginx`、`Apache`、`Jetty`、`Microsoft-IIS`、
`ProFTPD`、`vsftpd`、`Pure-FTPd`、`MySQL`、`Redis`），版本号保留原样（如 `8.9p1` 不截成 `8.9`），
`os_hint` 只在 banner 提供明确线索时给出（`(Ubuntu)`、`Debian-1`、`Microsoft-IIS` → `Windows`）。

---

## 6. 规则体系（识别规则与程序代码解耦）

**规则是数据，代码只是解释器。** 新增协议/产品只改 `rules/*.json`，不写 Go、不重新编译逻辑；
规则文件通过 `go:embed` 编进二进制（镜像无需挂载即可运行），也支持外部覆盖：

```bash
go run ./cmd/server -rules-dir ./my-rules   # 改规则不必改代码，也不必重新出镜像
```

### 6.1 数据模型

| 字段 | 含义 |
|---|---|
| `probes[].all` | 全部必须命中的断言 |
| `probes[].any` | 至少命中一条 |
| `probes[].none` | 一条都不能命中（负样本抑制） |
| `match.type` | `prefix`（不区分大小写字节前缀）/ `contains` / `regex`（RE2，作用于**原始字节**，可写 `\x00`）/ `hex`（含 `offset`，可做二进制定位） |
| `probes[].base_confidence` | 该协议证据的基础置信度 |
| `probes[].ports` | 端口先验，**只加分不否决** |
| `probes[].default_product` | 没有产品规则命中时的默认产品（如 Redis：协议即产品） |
| `products[].regex` | RE2 镜像，`$1`/`${name}` 取捕获组 |
| `products[].product` / `version` | 输出模板：字面量或捕获组 |
| `products[].weight` | 该产品证据的置信度增量（默认 0.12，显式 0 表示命名但不加分） |
| `os_hints[]` | 顺序敏感的 OS 词表（具体 → 笼统），在整条 banner 上匹配 |
| `version` | 规则集版本，出现在 `/health` 与日志里，便于回溯"这批结果用的哪版规则" |

启动时 `rules.Validate()` 会校验：probe id 唯一、协议非空、证据非空、所有正则/hex 可编译、
属性范围合法；**任何问题直接启动失败**（fail fast），不允许带病对外服务。

### 6.2 新增一条规则，3 步（示例：加 `Cockpit` 这个 HTTP 产品）

1. 在 `rules/protocols.json` 的 `http` probe 的 `products` **前面**插入（越靠前越优先）：

```json
{ "regex": "(?i)\\bcockpit/([0-9][0-9a-z.\\-_]*)", "product": "Cockpit", "version": "$1" }
```

2. 若是一个全新协议，加一个 probe：

```json
{
  "id": "example", "protocol": "EXAMPLE",
  "any": [{ "type": "regex", "value": "(?i)^EXAMPLE/[0-9]" }],
  "base_confidence": 0.72, "ports": [9999],
  "products": [{ "regex": "(?i)example/([0-9.]+)", "product": "Example", "version": "$1" }]
}
```

3. `go test ./...`（golden 测试 + 规则校验会自动跑），必要时补一条 `examples/expected.json`。

> 之所以代码里没有出现任何 `if strings.Contains(banner, "nginx")` 这样的分支：
> 所有"什么长得像谁"的知识都在 JSON 规则里，代码里只剩下通用匹配器与打分器。

---

## 7. 置信度模型

```text
confidence = clamp(
      base(协议证据强度)                  # 强魔术字 0.70~0.82，弱特征 0.65，端口从不单独作为证据
    + product_weight                     # 命中产品规则：默认 0.12（规则可覆盖，0 表示只有名字不加分）
    + 0.05  (version != "")              # 版本号被成功抽出
    + 0.05  (os_hint != "")              # OS 线索被识别
    + 0.05  (port ∈ probe.ports)         # 端口与协议先验一致
    , 0, 0.99)
unknown  → protocol="unknown"，confidence ∈ [0.00, 0.10]
```

拆解几个真实样本：

| 输入 | 计算 | 结果 |
|---|---|---|
| `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3` :22 | 0.70 + 0.12 + 0.05 + 0.05 + 0.05 | **0.97** |
| `Server: nginx/1.24.0` :80 | 0.70 + 0.12 + 0.05 + 0 + 0.05 | **0.92** |
| `Server: nginx/1.18.0 (Ubuntu)` :80 | 0.70+0.12+0.05+0.05+0.05 | **0.97** |
| `-ERR wrong number of...` :6379 | 0.65 + 0(产品权重为 0) + 0 + 0 + 0.05 | **0.70** |
| `\x16\x03\x01\x00\xa5...` :9999 | 0.70（无产品/版本/OS，端口不在先验内） | **0.70** |
| `QUIT\r\n` :12345 | 无 probe 命中 | **0.10 (unknown)** |

**端口为什么不扣分**：示例数据里 443 回的是明文 `HTTP/1.1`、8443 是 nginx 明文、9999 是 TLS 二进制。
端口是"相关性弱、误判成本高"的证据，用它否决会直接判错。因此只做正向加成。

---

## 8. 容器与部署

### 8.1 一键启动与依赖

```yaml
services:
  server:  # 只 expose 8080，不 ports
    healthcheck:
      test: ["CMD", "/app/server", "-healthcheck", "-addr", ":8080"]
      interval: 5s
      timeout: 3s
      retries: 4
      start_period: 2s
  client:
    depends_on:
      server: { condition: service_healthy }   # 真健康检测，不是 sleeps
```

**为什么健康检查不用 `curl`**：运行镜像是 `scratch`，里面没有 shell、没有 curl/wget、没有 libc。
所以健康检查由二进制自己的 `-healthcheck` 模式实现：向 `127.0.0.1:8080/health` 发一次**真实 HTTP 请求**，
非 200 则退出码 1。这比 `wget -q --spider` 更准确（真的走了一遍业务路由），也不需要给生产镜像塞工具。

### 8.2 评估关注点的落地

| 关注点 | 实现 |
|---|---|
| **容器间访问收敛** | server 只 `expose`，不 `ports`；client 用服务名 `http://server:8080`；自定义 bridge 网络且 `internal: true`（无外网出口）；宿主机访问只存在于显式 `-f docker-compose.debug.yml` 且绑 `127.0.0.1` |
| **启动依赖的真实健康检测** | `/health` 真实探测 + `service_healthy` 门控 + `start_period/interval/timeout/retries`；`/health` 里还带 `probes`、`rules_version`、`uptime` |
| **镜像的编译打包理解** | 两阶段构建；`CGO_ENABLED=0` 纯静态二进制 → `scratch`（**server 9.9MB / client 8.6MB**）；`-trimpath -ldflags="-s -w"`；`-X main.version` 注入版本；依赖层（`go.mod`）与源码层分离；`.dockerignore` 排除 `.git` 保证缓存命中；单 Dockerfile 多 target，client 镜像不含服务端代码 |
| **运行权限收紧** | `read_only: true` 根文件系统（程序不落盘，日志走 stdout）+ `tmpfs /tmp`；`user: 65532:65532`（镜像内 `USER 65532` 双保险）；`cap_drop: [ALL]`；`no-new-privileges:true`；`cpus/memory` 限额；`stop_grace_period` + SIGTERM 优雅退出；`json-file` 日志轮转 |
| **规则与代码解耦** | 规则是 JSON 数据 + `go:embed` / `-rules-dir`；启动即校验与编译；新增协议零代码改动（见 §6） |

### 8.3 构建

```bash
docker build --target server -t banner-fingerprint/server .   # ~9.9MB, scratch, nonroot
docker build --target client -t banner-fingerprint/client .   # ~8.6MB
docker buildx build --platform linux/amd64,linux/arm64 --target server .   # 多架构可用
```

---

## 9. 鲁棒性设计（这批数据最容易踩的坑）

1. **同一份 banner 的三种形态**：真实字节 / 字面量 `\x00` / JSON `\u0000`。
   `banner.Decode` 统一还原，且 `\u00NN` 按**单字节**处理
   （否则 `\u00a5` 会被编码成 UTF-8 两字节，二进制 banner 直接损坏）。
2. **非严格 JSON**：题目给出的自测数据里 `"J\x00\x00\x00\n8.0.32\x00"` 在 JSON 里是非法的
   （`\x` 不是合法转义）。`model.sanitizeJSON` 会在解析前把 `\xNN` 改写成字面量，再交给归一化层还原；
   裸控制字符也一并修复。对合法 JSON 完全是空操作。
3. **`strings.ToLower` 会破坏二进制**：小写视图是逐字节 ASCII 只对小写 A-Z 变换，非法 UTF-8 原样保留。
4. **不猜**：没有任何证据 → `unknown` + 低置信度；`QUIT\r\n`（客户端命令回显）这类"看起来像 FTP"的负样本
   不会被判成 FTP（命令词不能当服务端证据）。
5. **永不 crash**：`pipeline` 对单条做 panic 隔离、`api` 对整请求做 recover、
   超长 banner 截断到 64KB、批量与包体都有上限，`unknown` 是合法返回值而非错误路径。
6. **顺序与条数契约**：并发识别但结果按索引回填，`client` 还会校验 `len(resp) == len(req)`。
7. **规则坏了就别启动**：正则编译失败、版本冲突、字段非法 → 启动即失败（fail fast）。

---

## 10. 测试

```bash
go test ./...        # 单元测试 + golden test（20 条自测数据全字段比对）
go vet ./...
```

| 测试 | 覆盖点 |
|---|---|
| `internal/engine/engine_test.go` | golden 20 条（协议/产品/版本/OS/置信度下界）、三种 banner 编码、脏输入不 panic、unknown 语义、端口不否决证据 |
| `internal/banner/banner_test.go` | 转义还原、`\u00NN` 单字节、非法 UTF-8 保真、截断、摘要转义 |
| `internal/model/model_test.go` | 数组/包装/单对象/NDJSON、字段别名、base64 banner、非法 JSON 修复、错误路径 |
| `internal/api/api_test.go` | 批量与顺序、脏数据不影响整批、400/413/404/405、`/health` 与 `/version` |

另一个自测文件 `examples/input_edge.json` 覆盖：字符串端口、base64 banner、空 banner、缺 banner、
SMTP/VNC/Telnet/Memcached/Elasticsearch、中文文本 unknown 等。

---

## 11. 已知限制

- 只做**单包识别**，不主动发包，不做多轮握手（因此 TLS 只能给协议、给不出产品）；
- HTTP 只解析 `Server` 头，不解析 `X-Powered-By`、标题、Cookie 等次要线索（可加规则，无需改码）；
- `os_hint` 依赖 banner 中的显式线索（发行版标记、厂商名），没有线索时留空而不是猜；
- 端口 0 或缺失时不影响识别，只是少 0.05 的端口加成。

## 12. 配置项

| server flag | 环境变量 | 默认 | 说明 |
|---|---|---|---|
| `-addr` | `BFP_ADDR` | `:8080` | 监听地址 |
| `-rules-dir` | `BFP_RULES_DIR` | 空（用 embed） | 外部规则目录 |
| `-log-level` | `BFP_LOG_LEVEL` | `info` | `debug/info/warn/error` |
| `-max-items` | `BFP_MAX_ITEMS` | `20000` | 单请求最大条数 |
| `-healthcheck` | — | false | 自探活模式（容器 healthcheck 用） |
| `-version` | — | — | 打印构建版本 |

| client flag | 环境变量 | 默认 | 说明 |
|---|---|---|---|
| `-input` | `BFP_INPUT` | `input.json` | 输入文件 |
| `-server` | `BFP_SERVER` | `http://127.0.0.1:8080` | 服务端地址 |
| `-batch` | — | 500 | 每请求条数 |
| `-retries` | — | 3 | 5xx/网络错误的指数退避重试次数 |
| `-timeout` | — | 30s | 单请求超时 |
| `-json` | — | false | 输出机器可读 JSON |
| `-out` | — | 空 | 同时写文件（容器内只读文件系统下请用默认 stdout） |
