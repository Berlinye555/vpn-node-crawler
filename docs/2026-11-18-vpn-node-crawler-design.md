# VPN 节点爬虫设计文档

- 日期：2026-11-18
- 状态：待实施
- 目录：`g:\workspace\makemo\VPN\`

## 1. 目标

每天自动从公开渠道抓取 VPN/代理节点，按安全与可用性规则分层过滤，输出可直接导入客户端的订阅文件，并通过带密钥的固定 URL 提供订阅。

**非目标**：

- 不提供节点、不搭建代理服务、不绕过任何目标站点
- 不做带宽测速（运行环境为 GitHub Actions，测速结果无参考价值）
- 不做真实协议握手（需要引入代理内核，见第 3 节能力边界）

## 2. 合规声明

在中国大陆，使用未经批准的跨境 VPN 属于违规行为。本方案只做公开数据的抓取与格式转换，不鼓励、不协助违规用途；使用者自行承担使用后果。爬虫遵守数据源的公开访问约定：限速、带正常 User-Agent、不爬取需要登录的内容。

## 3. 能力边界（必须如实告知）

| 能力 | 能做 | 不能做 |
| --- | --- | --- |
| 恶意节点检测 | 校验 TLS 证书链、SNI 匹配、拒绝关闭证书校验的配置、识别内网地址指向 | 无法证明节点“不偷流量”，劫持行为只有实际使用才暴露 |
| 可用性 | TCP 连通 + TLS 握手 + 失败率统计 | 无法测真实带宽和真实延迟（Actions 在境外机房） |
| reality 节点 | TCP 连通探测 | reality 无证书可校验，安全性无法验证 |
| 明文协议 | 识别并剔除 http/socks 无 TLS | — |

## 4. 架构

模块化流水线，每层单一职责、独立可测：

```text
sources（四类抓取）
  → parsers（统一节点模型）
  → aggregator（去重、来源标记）
  → filters（四层过滤，逐层出漏斗统计）
  → renderers（Clash YAML / Base64）
  → deliver（Worker 上传）
```

任一数据源失败不影响整体；每一层都输出计数与原因，汇总到 `report.json`。

## 5. 目录结构

```text
VPN/
├── .github/workflows/daily.yml
├── config/
│   ├── sources.yaml      # 数据源清单 + 网页解析规则
│   ├── filters.yaml      # 过滤阈值、黑名单、协议策略
│   └── render.yaml       # 分组、命名、输出上限
├── vpnnode/
│   ├── __init__.py
│   ├── models.py         # Node 模型
│   ├── fetch.py          # HTTP 抓取（并发/重试/限速/UA）
│   ├── sources/
│   │   ├── github.py
│   │   ├── webpage.py
│   │   ├── subscription.py
│   │   └── telegram.py
│   ├── parsers/
│   │   ├── links.py      # vmess/vless/trojan/ss/hysteria2 链接
│   │   └── clash.py      # Clash proxies 段
│   ├── aggregator.py
│   ├── filters/
│   │   ├── precheck.py
│   │   ├── probe.py
│   │   ├── reputation.py
│   │   └── quality.py
│   ├── renderers/
│   │   ├── clash.py
│   │   └── base64.py
│   ├── deliver.py        # 上传到 Worker
│   └── pipeline.py       # 入口
├── worker/               # Cloudflare Worker 订阅服务
│   ├── src/index.ts
│   └── wrangler.toml
├── tests/
│   ├── fixtures/
│   └── test_*.py
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

## 6. 节点模型

```python
@dataclass
class Node:
    protocol: str        # vmess | vless | trojan | ss | hysteria2
    name: str
    server: str
    port: int
    params: dict         # uuid/password/cipher/network/tls/sni/ws_opts/...
    raw: dict            # 原始配置，全部保留用于回溯
    source: str          # 来源标识，如 "github:owner/repo"
    fingerprint: str     # sha256(protocol|server|port|凭据)
```

去重规则：按 `fingerprint` 哈希去重；同一节点保留“来源可信度最高”的那条（GitHub 聚合仓库 > 订阅 > 网页 > Telegram）。

解析失败不静默：计入 `report.json` 的 `parse_failed`，附带来源与原始片段前缀，用于发现某数据源格式变化。

## 7. 数据源

全部配置化在 `config/sources.yaml`，新增源不改代码。

| 类型 | 抓取方式 | 说明 |
| --- | --- | --- |
| `github` | `raw.githubusercontent.com` 拉取，带 `GITHUB_TOKEN` 提高限流额度 | 源清单是配置数据，实施第 2 阶段筛选 3～5 个每日更新、连续可用的聚合仓库写入 `sources.yaml`，本设计不锁定具体仓库 |
| `webpage` | httpx 拉 HTML，按配置的正则/CSS 选择器提取链接 | 解析规则写在 YAML，页面改版只改配置 |
| `subscription` | httpx 拉取，自动识别三种内容：base64 / Clash YAML / 纯文本链接 | 一个解析器吃三种格式 |
| `telegram` | 抓 `t.me/s/<channel>` 网页预览页，正则提取链接 | 不使用 Telethon/API，无需账号与凭据 |

抓取层统一：并发上限 20（Semaphore）、随机 User-Agent、超时 15 秒、失败重试 2 次（指数退避 1s/2s）、响应体大小上限 10MB。

## 8. 四层过滤

### 8.1 precheck（静态，不联网）

| 规则 | 结果 |
| --- | --- |
| 协议白名单之外（http、无 TLS 的 socks） | 剔除 |
| `allowInsecure: true` / `skip-cert-verify: true` | 剔除 |
| Clash 节点含 `script` / `javascript` 字段 | 剔除 |
| server 为 127/8、10/8、172.16/12、192.168/16、169.254/16、0.0.0.0、IPv6 回环与链路本地 | 剔除 |
| ss 加密为 `none`、`rc4-md5`、`rc4`、`table` 等弱算法 | 剔除 |
| server 非合法域名/IP、端口不在 1-65535 | 剔除 |

### 8.2 probe（联网，异步并发）

- 每个节点探测 2 次（`tcp_fail_threshold`）；2 次均失败剔除，至少 1 次成功则保留并取较优耗时
- TLS 节点：`asyncio.open_connection` + 系统 CA 校验证书链 + hostname 校验（SNI）
- 证书校验失败（自签、过期、域名不符）→ **默认剔除**；`filters.yaml` 可切 `tls_policy: strict | loose`，loose 下保留但标记 `self_signed`
- reality 节点跳过证书校验，标记 `tls_unverifiable`
- 并发 30，整体探测超时上限 15 分钟
- 记录握手耗时与错误类型到 `report.json`

### 8.3 reputation（联网）

- `socket.getaddrinfo` 解析 server 域名，取全部 A/AAAA 记录
- 归属查询：`ip-api.com/batch`（免费，45 次/分钟，单次 100 IP），得到国家、ASN、是否托管商
- DNSBL：dnspython 直查 `zen.spamhaus.org`；处理 127.255.255.x 保留码（视为查询失败而非命中）
- 命中黑名单 → 剔除；查询失败 → 标记 `unverified`，不阻塞
- 托管商（VPS）只打标签，不剔除（大多数机场本身就是 VPS）

### 8.4 quality（基于 8.2 结果）

- 连续 2 次探测失败剔除
- 握手耗时 > 3000ms 剔除（可配置）
- 同协议 + 同国家分组内按握手耗时排序，每组最多保留 N 个
- 全局输出上限 300 个（可配置）
- 质量分 = 握手耗时升序优先，不测带宽

## 9. 输出

- `clash.yaml`：`proxies` + `proxy-groups`（`🚀 自动` url-test 全量、`♻️ 手动`、按地区分组）+ 基础规则（局域网直连 → 国内直连 `GEOSITE,cn`/`GEOIP,CN` → `MATCH,🚀 自动`）
- `sub.base64`：标准链接列表（vmess/vless/trojan/ss/hysteria2），整体 base64
- `report.json`：漏斗统计（每层剔除数与原因分布）、失败源列表、检测时间
- 节点重命名为 `{地区代码}-{协议}-{序号}`，原始名称保存在 `raw`

测速由用户客户端完成：`url-test` 健康检查 URL 使用 `https://www.gstatic.com/generate_204`，间隔 300 秒。

## 10. 交付：Cloudflare Worker + KV

- KV namespace 存三个键：`clash.yaml`、`sub.base64`、`report.json`
- 读取：`GET /sub/<key>/clash.yaml`、`GET /sub/<key>/sub.base64`，key 与 Worker 环境变量比对，错误返回 404（不暴露存在性）
- 写入：`PUT /upload/<key>/<filename>`，Header `Authorization: Bearer <UPLOAD_TOKEN>`，限制 Content-Type 与大小（1MB）
- 上传后返回 `Cache-Control: public, max-age=3600`，读取可配 `no-store` 以便立即生效
- 密钥轮换：更换 Worker 环境变量即可，旧链接失效
- `report.json` 不通过订阅 URL 暴露，仅上传备查（可选读取）

## 11. GitHub Actions 工作流

```yaml
on:
  schedule:
    - cron: '17 21 * * *'   # 北京时间 05:17，避开整点
  workflow_dispatch:
timeout-minutes: 30
```

步骤：checkout → setup-python（3.12）→ pip install -r requirements.txt → `python -m vpnnode.pipeline` → 上传到 Worker → 上传 artifact（保留 7 天，备份）。

所需 Secrets：`SUB_ACCESS_KEY`、`UPLOAD_TOKEN`、`WORKER_BASE_URL`；`GITHUB_TOKEN` 由 Actions 自动注入，无需配置。

失败策略：数据源失败跳过并记入报告；若最终可用节点数为 0 或低于 20，任务标记失败（防止把空订阅推上线）。上传失败则重新执行一次，仍失败则任务失败、旧订阅保持不动。

## 12. 配置项（`config/filters.yaml` 摘要）

```yaml
tls_policy: strict          # strict | loose
probe_concurrency: 30
probe_timeout_s: 5
tcp_fail_threshold: 2
max_handshake_ms: 3000
max_nodes_total: 300
max_nodes_per_group: 30
dnsbl_zones: [zen.spamhaus.org]
reputation_enabled: true
reputation_fail_open: true  # 查询失败是否继续
```

## 13. 测试策略

- **解析器单测**：每个协议 3 个以上样本（含畸形输入），断言解析结果或明确异常
- **过滤器单测**：每条 precheck 规则一个用例；probe/quality 用本地伪服务或用例桩
- **端到端**：`tests/fixtures/` 放离线样本（各源格式各一份），跑完整 pipeline，断言输出结构和漏斗数字
- **Worker**：手测读写与鉴权，不强制自动化
- 测试不依赖外网：联网层用 mock

## 14. 错误处理与降级

| 故障 | 处理 |
| --- | --- |
| 某数据源 404/超时 | 跳过，记入 `failed_sources` |
| 解析异常 | 单条计入 `parse_failed`，继续 |
| IP 归属接口限流 | 降级为未检测，打 `unverified` 标签 |
| DNSBL 查询失败 | 同上 |
| 最终节点数过低 | 任务失败，不覆盖线上订阅 |
| Worker 上传失败 | 重试一次；仍失败则保留旧订阅 |

## 15. 实施阶段

1. 骨架：模型、fetch、解析器 + 单测
2. 抓取层：四类数据源 + `sources.yaml`
3. 过滤层：precheck → probe → reputation → quality
4. 输出层：Clash / Base64 渲染
5. Actions 工作流 + artifact
6. Worker 订阅服务 + Secrets 联调
7. README 与运维说明（如何换源、换密钥、调阈值）
