# VPN 节点爬虫设计文档

- 首次编写：2026-11-18
- 最近更新：2026-11-19（对齐实际实现）
- 目录：`g:\workspace\makemo\VPN\`

## 1. 目标

每天自动从公开渠道抓取 VPN/代理节点，经五层过滤后用真实请求验证可用性，输出可直接导入客户端的订阅文件，通过公开仓库 + jsDelivr 提供固定订阅地址。

**非目标**：

- 不提供节点、不搭建代理服务、不绕过任何目标站点
- 不测带宽（运行环境为 GitHub Actions，测速结果无法代表用户网络）
- 不在爬虫内实现协议握手（交给 mihomo 内核）

## 2. 合规声明

在中国大陆，使用未经批准的跨境 VPN 属于违规行为。本项目只做公开数据的抓取与格式转换，不鼓励、不协助违规用途；使用者自行承担使用后果。爬虫遵守数据源公开访问约定：限速、带正常 User-Agent、不抓取需要登录的内容。

## 3. 能力边界（必须如实告知）

| 能力 | 能做 | 不能做 |
| --- | --- | --- |
| 配置安全 | 剔除明文代理、跳过证书校验、脚本注入字段、私网地址、弱加密、废弃 XTLS flow | 无法证明节点"不偷流量" |
| TLS 校验 | 校验证书链与 SNI；区分证书错误和连接失败 | reality 无证书可校验 |
| WS 后端 | 真实 WebSocket Upgrade，识别"入口活着但后端已死"的 CDN 中转节点 | 无法验证 UUID 认证是否正确 |
| 真实连通 | 用 mihomo 内核真实发 HTTP 请求，按成功率筛节点 | 运行在境外机房，**无法代表国内网络可达性** |
| 速度 | — | 不测带宽（见非目标） |

## 4. 架构

```text
sources          抓取（GitHub raw / 订阅链接；webpage、telegram 为预留能力）
  → parsers      统一节点模型（vmess/vless/trojan/ss/hysteria2）
  → aggregator   按来源优先级去重
  → precheck     静态安全检查（不联网）
  → probe        TCP + TLS 证书 + WebSocket 握手
  → reputation   DNS 解析、IP 归属、DNSBL 黑名单
  → alive        mihomo 内核真实 HTTP 请求验证
  → quality      失败阈值、分组/总量限额、排序与命名
  → renderers    Clash YAML + Base64
  → deliver      提交回仓库（jsDelivr 交付）；Worker 上传为可选
```

任一数据源失败不影响整体；每层输出计数与原因，汇总到 `report.json`；每层打印耗时（`stage <name> <秒>`）。

## 5. 目录结构

```text
VPN/
├── .github/workflows/daily.yml   # 每日定时任务
├── config/
│   ├── sources.yaml              # 数据源清单
│   └── filters.yaml              # 过滤阈值
├── vpnnode/
│   ├── models.py                 # Node 模型、指纹、分享链接生成
│   ├── fetch.py                  # HTTP 抓取（重试/UA/大小上限）
│   ├── aggregator.py             # 去重
│   ├── pipeline.py               # CLI 与流水线
│   ├── deliver.py                # Worker 上传（可选路径）
│   ├── sources/                  # github / subscription / webpage / telegram
│   ├── parsers/                  # links.py（分享链接）/ clash.py（YAML）
│   ├── filters/                  # precheck / probe / reputation / alive / quality
│   └── renderers/                # clash.py / base64_sub.py
├── worker/                       # 可选：私密订阅（Cloudflare Worker + KV）
├── tools/push_via_api.py         # 网络受限时的 API 推送工具
├── tests/                        # 72 个测试
└── docs/                         # 本设计文档
```

## 6. 节点模型

```python
Node: protocol, name, server, port, params, raw, source
fingerprint = sha256(protocol|server|port|凭据|cipher|network|ws_path|sni)
```

指纹包含传输与加密参数，避免"同一端点不同配置"被错误合并后留下坏配置。

解析失败不静默：Clash 条目逐条容错，畸形条目跳过并记日志。

## 7. 数据源

全部配置化在 `config/sources.yaml`。

| 类型 | 当前启用 | 说明 |
| --- | --- | --- |
| `github` | freefq、ripaojiedian、ermaozi、anaer/Sub、mahdibland Eternity、passcro、hermanb001（jingfu/hellopool）、YasserDivaR、xiyaowong、peasoft | 抓 raw.githubusercontent.com；源内并发；token 只发给 GitHub 域名 |
| `subscription` | leidahub.top | 第三方聚合订阅 |
| `webpage` | 未启用 | 按正则提取，页面改版只改配置 |
| `telegram` | 未启用 | t.me/s/ 网页预览，无需账号 |

抓取策略：源内并发、重试 1 次、超时 10～25 秒、响应体上限 10MB。不启用 jsDelivr 镜像源——Actions 环境 raw 可达，镜像只会造成重复抓取。

## 8. 五层过滤

### 8.1 precheck（静态）

| 规则 | 原因码 |
| --- | --- |
| 协议不在白名单 | `unsupported_protocol` |
| 端口非法 | `invalid_port` |
| 私网/保留地址、内网域名 | `private_address` |
| 含 script/javascript 字段 | `script_field` |
| allowInsecure / skip-cert-verify | `insecure_tls` |
| 缺少 uuid/password/cipher | `missing_credentials` |
| ss 弱加密 | `weak_cipher` |
| vless 废弃 flow（xtls-rprx-direct 等） | `unsupported_flow` |

### 8.2 probe（TCP + TLS + WS）

- 非 ws 节点：TCP connect；TLS 节点完整校验证书链，区分"证书错误"与"连接失败"
- **ws 节点**：发送真实 WebSocket Upgrade（正确的 Host/Path/Key）
  - 101 → 后端存活
  - 4xx/5xx → `ws_dead`（CDN 中转后端已死）
  - 其他/超时 → 保守放过
- 每节点探测 `tcp_fail_threshold` 次（默认 2），任一成功即通过
- 连接关闭有 1 秒超时保护，避免挂起

### 8.3 reputation

- `getaddrinfo` 解析全部 IP
- `ip-api.com/batch` 查国家、ASN、是否托管商（失败降级为未检测）
- DNSBL 查 `zen.spamhaus.org`（`dnsbl_zones` 可配），**专用 64 线程池**，最多查 1500 个 IP
- 命中黑名单剔除；查询失败记 `dnsbl_unverified`，不阻塞

### 8.4 alive（mihomo 真实测试）

- Actions 中下载 mihomo 内核，加载全部候选节点
- 通过 `/proxies/{name}/delay` 对每个节点真实发 HTTP 请求（`generate_204`）
- 采样 `alive_samples` 次（默认 1），成功率低于 `alive_min_success_rate` 剔除
- 原因码：`dead_proxy`（0 次成功）、`unstable_proxy`
- **专用线程池**（规模 = `alive_concurrency`）；2 核 runner 的默认线程池只有 6 个线程，会把手动并发压死
- 整批配置被内核拒绝时按 200 个一组降级重试（最多 3 批）
- 内核不可用时整层跳过，流水线继续

### 8.5 quality

- 连接失败、坏证书、`ws_dead`、握手超时剔除
- 按握手耗时排序；无国家信息的节点不受单组上限约束
- `max_nodes_per_group`（默认 30）、`max_nodes_total`（默认 300）
- 统一命名 `{国旗} {国家} {序号}`，序号按延迟升序

## 9. 输出

- `clash.yaml`
  - 头部：`tcp-concurrent`、`unified-delay`、fake-ip DNS（国内 DoH）、`geox-url` jsDelivr 镜像
  - 规则：`GEOSITE,private` → `GEOIP,private` → `GEOSITE,cn` → `GEOIP,CN` → `MATCH,🚀 自动`
  - 分组：自动（url-test）、手动、按国家分组
  - 节点字段透传：`client-fingerprint`、`reality-opts`、`obfs`、`grpc-opts`、`xhttp-opts`、`plugin` 等；布尔与嵌套字段做类型规范化
- `sub.base64`：标准分享链接，v2rayN 可用
- `report.json`：漏斗统计、失败源、被剔除样本、**分阶段耗时**、**每源抓取数与最终贡献**

测速交给客户端（`url-test` 指向 `gstatic/generate_204`）。

## 10. 交付

### 主路径：公开仓库 + jsDelivr

```text
Clash:  https://gcore.jsdelivr.net/gh/Berlinye555/vpn-node-crawler@main/output/clash.yaml
v2rayN: https://gcore.jsdelivr.net/gh/Berlinye555/vpn-node-crawler@main/output/sub.base64
```

- Actions 每天把 `output/` 提交回仓库，并调用 purge 接口刷新缓存
- **jsDelivr 对 `@分支` 的指针缓存 12 小时且 purge 不清**：固定地址会滞后；需要立即生效时用 `@commit-sha` 地址
- 镜像域名：gcore / testingcf 可用；fastly 缓存滞后明显，cdn 国内常不可达

### 可选：Worker 私密订阅（`worker/`，未启用）

- KV 存储 + 带密钥 URL，节点不公开
- 代价：workers.dev 国内不稳，通常需自定义域名；主流程用 `--no-upload` 跳过

## 11. GitHub Actions

```yaml
on:
  schedule: [{cron: "17 21 * * *"}]   # 北京时间 05:17
  workflow_dispatch:
```

步骤：checkout → setup-python 3.12 → 安装依赖 → 下载 mihomo（失败不阻塞）→ 运行流水线 → 提交 output → purge jsDelivr → 失败时上传 artifact。

`min_nodes`（默认 20）在写文件前校验：低于阈值直接失败，不覆盖已有订阅。

## 12. 配置项

`config/filters.yaml`：TLS 策略、探测并发/超时、失败阈值、总量与分组上限、DNSBL、alive 采样与并发。

## 13. 测试

72 个测试，覆盖解析器（含畸形输入）、各层过滤器、渲染器、端到端离线流水线、alive 过滤逻辑。测试不依赖外网。

## 14. 错误处理

| 故障 | 处理 |
| --- | --- |
| 数据源失效/超时 | 跳过并记日志，不影响其他源 |
| 单条畸形节点 | 逐条跳过，不中断解析 |
| ip-api 限流 | 降级为未检测，继续 |
| DNSBL 查询失败 | 标记未验证，继续 |
| mihomo 启动失败 | 整批失败则分批重试；仍失败则跳过该层 |
| 最终节点数不足 | 任务失败，旧订阅保持 |
| 上传失败 | 重试一次；仍失败任务失败 |

## 15. 演进记录

| 时间 | 变更 | 原因 |
| --- | --- | --- |
| 11-18 | 初版：四层过滤 + Worker 交付 | — |
| 11-19 | 交付改为公开仓库 + jsDelivr | workers.dev 国内不可达 |
| 11-19 | 渲染层字段透传白名单 | reality/obfs/grpc 参数丢失导致"能导入不能用" |
| 11-19 | probe 增加 WebSocket 握手 | CDN 中转节点 TCP/TLS 永远通过、后端已死 |
| 11-19 | 新增 alive 层（mihomo） | 前四层无法验证协议层，87% 死节点漏网 |
| 11-19 | 多次采样改为单次 | 3 次采样让 CI 从 2 分钟涨到 12 分钟 |
| 11-19 | DNSBL/alive 改用专用线程池 | 默认线程池在 2 核 runner 上只有 6 线程 |
| 11-19 | 数据源扩充到 11 个，移除零贡献源 | 来源统计显示 LonUp/jiang 存活率 0% |
