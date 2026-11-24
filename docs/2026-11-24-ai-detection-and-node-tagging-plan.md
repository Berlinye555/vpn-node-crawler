# Telegram 扩源 · AI 平台 IP 干净度检测 · 节点分级打标

- 日期：2026-11-24
- 状态：P1–P3 已实施；P4–P5 待做（见第 10 节）
- 关联：[2026-11-18-vpn-node-crawler-design.md](2026-11-18-vpn-node-crawler-design.md)

本文只做设计，不改代码。三块能力的共同前提是：**现在的流水线只判断「节点能不能连」，新增的三块要回答「节点从哪来、IP 干不干净、适合干什么」。**

---

## 0. 先说三条结论

1. **Telegram collector 不需要 API 凭据。** `vpnnode/sources/telegram.py` 抓的是 `https://t.me/s/<channel>` 公开预览页，走 HTTP + HTML，无需 bot token、无需 tgstat。通道已经在 `FETCHERS` 里注册，**加频道只需改 `config/sources.yaml`**。真正的工程量在「HTML 清洗」和「频道筛选」，不在鉴权。
2. **AI 干净度不能靠 `node.server` 解析出的 IP 判断。** 免费节点里大量是 WS+TLS+CDN 中转，`server` 是 CDN 入口，不是出口。必须**经节点真实请求**拿到出口 IP（`cloudflare/cdn-cgi/trace` 返回 `ip=`），再去查 IP 情报。这是本方案最大的架构变化：从「静态解析 IP」升级到「实测出口 IP」。
3. **安全 / AI 可用 / 速度是三个正交维度，不要合成一个“等级”。** 一个节点可以「安全但 AI 被墙」「不安全但极快」。正确做法是**多维标签 + 组合分组**：节点名带标签，Clash 里按用途分组（AI 优选组、住宅组、安全组、延迟组）。

---

## 1. 现状盘点

| 层 | 现有能力 | 缺口 |
| --- | --- | --- |
| 抓取 | github / subscription / telegram / webpage 四类 | telegram 未启用；无频道清单维护 |
| 静态检查 | 明文、弱加密、跳过证书校验、私网地址、脚本注入 | 无 |
| 探测 | TCP/TLS/WS 握手、证书有效性、握手耗时 | 无 |
| IP 信誉 | `node.server` DNS 解析 → ip-api `hosting` + Spamhaus DNSBL | 查的是**入口 IP**；未用 `proxy` 字段；未查滥用历史 |
| 真实请求 | mihomo `/proxies/{name}/delay` 测 `generate_204` | 只有「通/不通/延迟」，不区分目标站点，不拿响应内容 |
| 质量限额 | 全天候延迟排序 + 国家分组限额 | 无 |
| 输出 | `clash.yaml` / `sub.base64` / `report.json` / `history` | 无分级标签、无按用途分组、无单节点明细 |

现有可复用的两个抓手：

- `alive.py` 已经能起 mihomo 实例并批量测节点 —— 新增检测应**复用同一次实例启动**，不要重复拉起。
- `Node.params` 是自由 dict，`renderers/clash.py` 的 `_to_clash` 只用白名单字段，所以**给节点挂 `score`/`ai_ok`/`ip_type` 这类私有键不会污染输出**，可以放心加。

---

## 2. 能力一：Telegram 频道抓取

### 2.1 原理与限制

`t.me/s/<channel>` 是 Telegram 的网页预览，匿名可读，返回纯 HTML。已知约束：

| 约束 | 影响 | 应对 |
| --- | --- | --- |
| 每页约 20 条消息 | 一天发几十条的频道抓不全 | 用 `?before=<message_id>` 翻页，抓最近 N 页 |
| HTML 会把 URI 放在 `<span>`/`<br>` 里并转义 `&amp;` | 正则可能截断链接 | 抓取后先剥标签、再 unescape，最后交给 `parse_any_text` |
| 频道可能删除历史消息 | 抓到的比实际少 | 每日全量重抓，不依赖增量 |
| 国内直连 `t.me` 超时 | 本地无法调试 | 只在 GitHub Actions 或代理下验证；本地调试走 `HTTPS_PROXY` |
| 部分频道要求加入才能看 | 预览页为空 | 启动前校验 HTML 里是否有 `tgme_channel_info`，没有就标记失效 |

本次实测：本地 `t.me` 全部超时（国内网络），`t.me/s/` 的可达性只能在 CI 验证。

### 2.2 现有代码要补的点

| 位置 | 改动 |
| --- | --- |
| `sources/telegram.py` | 增加 `?before=` 翻页；抓完先做 HTML 剥标签清洗；记录 `empty preview` 与 `404` 两种失败原因 |
| `sources/common.py` | 增加一个 `strip_html()`（去掉 `<script>`/`<style>`/标签、还原实体），供 telegram 与 webpage 共用 |
| `config/sources.yaml` | 启用 `type: telegram` 条目，支持一个 spec 多个频道 |
| `pipeline.py` | 无需改动，`FETCHERS` 已注册 |

### 2.3 频道清单怎么定（这一步比代码重要）

不要凭印象写频道名。建议流程：

1. 候选频道先放在 `config/sources.yaml` 的 telegram 条目里，**CI 首轮跑完看 `report.json` 的 `fetched_by_source`**，`telegram:<channel>` 产出为 0 的直接删。
2. 每轮记录「抓取数 / 去重后 / 最终存活数」，存活率长期为 0 的频道移除。这与之前删掉 `lonup`/`jiang` 的判据一致。
3. 已知可用的一个：`freenodedaily`（openrunner 的频道，每天 12–24 条）。其余候选需要在 CI 实测，本文不臆造。

### 2.4 配置草案

```yaml
- type: telegram
  timeout: 20
  max_pages: 3          # 新增：默认 1，抓 3 页约 60 条
  channels:
    - freenodedaily
    - <候选频道>
```

### 2.5 风险

- 频道内容可能夹带推广链接、其他格式，`parse_any_text` 会自动忽略非节点 URI，安全。
- `t.me/s/` 对高频访问有软限流，单次跑一次不会触发。

---

## 3. 能力二：AI 平台 IP 干净度检测

### 3.1 AI 平台到底在判什么

根据 2026 年的公开资料，ChatGPT / Claude 的「Unusual activity」「Suspicious activity」**绝大多数是出口 IP 的风险分触发**，而不是账号问题。综合信号：

| 信号 | 说明 | 可检测性 |
| --- | --- | --- |
| 数据中心 ASN | AWS/GCP/阿里云等云厂商出口默认高危 | ✅ 可查 |
| 公开 VPN/代理库收录 | 共享免费代理基本都在库里 | ✅ 可查 |
| IP 滥用历史 | 垃圾邮件、扫描、攻击 | ✅ 部分可查 |
| Tor 出口 | 基本一票否决 | ✅ 可查 |
| 地域跳跃 | 同账号短时间跨洲登录 | ❌ 与节点无关 |
| 浏览器/ TLS 指纹 | headless、非浏览器 JA3 | ⚠️ 会干扰判定，需模拟 |
| Cloudflare 挑战 | `challenges.cloudflare.com` 脚本被拦 | ⚠️ 只能看结果 |

**关键推论：TLS 指纹会污染我们的探测结果。** mihomo 只是转发字节流，如果客户端是 `urllib`，JA3/JA4 明显不是浏览器，Cloudflare 可能在「IP 其实干净」时也返回 403。所以探测端不能用 `urllib`，应当用能模拟 Chrome 指纹的客户端（如 `curl_cffi` 的 `impersonate="chrome"`），否则 403 的归因会大面积失真。

### 3.2 三个层次的信号（由便宜到贵）

```
L1  IP 情报     不经过节点，只查 IP 属性          —— 便宜，但不能反映出口
L2  出口 IP     经节点访问 trace 拿真实 IP        —— 中等，解决 CDN 中转误判
L3  目标可达    经节点访问 AI 站点看状态码/响应    —— 最贵，最接近真实体验
```

**L1 单独用会错**：中转节点的入口 IP 是 Cloudflare 段，被判「数据中心」并不代表出口脏；反过来直连节点的入口就是出口，才准确。所以 L1 只能对「直连节点」直接用，中转节点必须走 L2。

### 3.3 技术方案：一次 mihomo 实例，每节点一个本地端口

mihomo 的 `listeners` 支持 `proxy:` 字段，把某个本地端口固定绑定到某个出口，绕过 `rules`：

```yaml
listeners:
  - {name: l00001, type: mixed, port: 20001, listen: 127.0.0.1, proxy: n00001}
  - {name: l00002, type: mixed, port: 20002, listen: 127.0.0.1, proxy: n00002}
```

这样**同一个进程**既能给 alive 层用 `/proxies/{name}/delay`，又能给 AI 检测用 `127.0.0.1:20001` 发真实 HTTP 请求，只启动一次内核。

流程：

```
build_config() 增加 listeners（每个节点一个 mixed 端口）
  → 启动 mihomo（现有逻辑）
  → alive 阶段（现有，/proxies/{name}/delay）
  → 新增 probe_exit 阶段：
      对每个存活节点，并发经其端口请求：
        a) https://www.cloudflare.com/cdn-cgi/trace   → 解析 ip= / loc= / warp=
        b) https://chatgpt.com/cdn-cgi/trace          → 状态码 + 是否 challenge
        c) https://claude.ai/cdn-cgi/trace            → 状态码
        d) https://api.openai.com/v1/models           → 401 / 403 / 000
        e) https://api.anthropic.com/v1/models        → 401 / 403 / 000
  → 汇总出口 IP，批量查 ip-api（已有 batch 接口）
  → 生成 AI 干净度评分
```

端口数控制：节点通过 alive 后通常几十到两百个，一批 50 个 listener 滚动复用即可，不必给全部 300 个都开端口。

### 3.4 探测判定表

| 探测项 | 期望 | 含义 |
| --- | --- | --- |
| `cloudflare/cdn-cgi/trace` | 200，body 含 `ip=` | 拿到出口 IP；`warp=on` 说明是 WARP 出口 |
| `chatgpt.com/cdn-cgi/trace` | 200 | 能到 CF 边缘。403 + `Just a moment` = 被挑战 |
| `api.openai.com/v1/models` | **401** | 401 = IP 未封但缺 key，是最健康的状态 |
| 同上 | 403 | IP 被 OpenAI/CF 风控 |
| 同上 | 000 / 超时 | 不通 |
| `api.anthropic.com/v1/models` | 401 / 403 / 000 | 同上语义 |
| `claude.ai/cdn-cgi/trace` | 200 | Claude 前端可达 |

> 注意：401 和 403 的语义要用**同一出口的对照组**校准。本次实测本机 `api.anthropic.com` 返回 403 而非 401，说明该 URL 的状态码会随 IP 变化，不能写死「401 才算通」，要以「同一批里多数节点的众数」或「已知干净出口」为基准。

### 3.5 评分模型（建议）

```
ai_score = 50×可达性 + 30×(1 - risk) + 20×非数据中心
```

| 子项 | 取值 |
| --- | --- |
| 可达性 | ChatGPT 与 Claude 各 25 分，按状态码给满/半/零 |
| risk | ip-api `proxy` 为 true 扣满；`hosting` 为 true 打七折；DNSBL 命中一票否决 |
| 非数据中心 | `hosting=false` 满分；`hosting=true` 零分 |

输出三档：

| 等级 | 条件 | 标签 |
| --- | --- | --- |
| AI 干净 | 两个 AI 站点 401/200，且 `proxy=false`、`hosting=false` 或仅 CDN | 🤖✅ |
| AI 受限 | 能连但 403/challenge，或 IP 被标记 proxy/hosting | 🤖⚠️ |
| AI 不可用 | ChatGPT 与 Claude 均 000 | 🤖❌ |

### 3.6 必须写清楚的两个失真点

1. **CDN 中转节点测不出真实落地 IP。** `cdn-cgi/trace` 返回的是 CDN 出口。这类节点标记为 `☁️ CDN中转`，单独归类，**不参与「住宅 IP」评定，也不因 Cloudflare 段被判为脏**。
2. **TLS 指纹对结果影响很大。** 必须用模拟浏览器的客户端；若 CI 里装不了 `curl_cffi`，退化为「只信 IP 情报、AI 可达只作参考」，并在 `report.json` 里注明 `ai_probe: "degraded"`。

### 3.7 成本估算（GitHub Actions，30 分钟预算）

| 阶段 | 节点数 | 并发 | 预估耗时 |
| --- | --- | --- | --- |
| 出口 IP + AI 探测 | 通过 alive 的节点，约 50–200 | 30 | 30–60 s |
| ip-api 批量查询 | 出口 IP 去重后 | 100/批，15 批/分 | 5–15 s |
| （可选）吞吐测速 | 最终入选，≤300 | 10 | 2–5 min |

现有 alive 阶段本就耗时，新增部分控制在 **2 分钟内**是可行的；超时风险主要来自「节点极慢但不断连」，所以每次探测要硬超时（建议 5 s）。

### 3.8 第三方纯净度平台（ippure / ipure.dev）能不能直接用

结论：**能，但三种用法差别很大，推荐的只有第三种。**

#### （1）ippure.com 的私有接口 —— 能调通，但不建议做依赖

实测结论（2026-11-24）：

- 站点是 SPA，查询走 `POST https://api.ippure.com/api/info/ip-batch-abstract`，body 为 `{"IPs": [...]}`，**支持批量**。
- 接口有防滥用设计：首次请求服务端在响应头下发 `x-k`（密钥）和 `x-t`（服务器时间戳），后续请求需带 `x-k` 与 `x-t: <ts>-<HMAC-SHA256(method-url-body-ts, x-k)>`，且 **body 要先用 `AES-CBC(key=SHA256(x-k))` 加密**。算法全部明文在前端 JS 里，签名可复现。
- 但这是**无文档、无 SLA、无授权条款的私有接口**，签名和加密本身就是运营方的批量限制意图，随时可能改版或封 IP。

→ 只适合人工在浏览器里查个别 IP，**不适合放进每天自动跑的流水线**。

#### （2）ipure.dev 的公开 API —— 合规，但额度撑不起全量

有正式文档的接口：

| 接口 | 说明 |
| --- | --- |
| `GET /api/v1/ip/{ip}` | 完整报告：`purity` 0–100、`level`、`verdict`、`usage_type`、`native_type`、`flags{is_proxy,is_vpn,is_tor,is_hosting,is_relay}`、`proxy_assessment`、`asn`、滥用记录、逐项扣分依据 |
| `GET /api/v1/ip/{ip}/history?limit=N` | 历史检测记录（只读，不重新检测、不耗额度） |

额度与限制（实测确认）：

- **匿名只能读「已收录」的报告**，未收录 IP 与 `refresh` 必须带 `X-API-Key`；匿名普通查询 30 次/分钟。
- 有 key：**100 次 / UTC 日、10 次/分钟**，成功和 429 都带 `X-API-Key-*` 头。
- **没有批量接口**，一次一个 IP。

→ 我们的节点出口 IP 绝大多数是冷门地址（未收录），全量查询需要 key 且额度远远不够。**只适合终选节点（几十个）的二次复核**。

#### （3）复刻它的机制 —— 推荐，成本最低且可控

ippure 的「纯净度」不是黑箱，就是**100 分起扣的聚合评分**，判据全部来自公开数据源：

| 数据源 | 用途 | 获取成本 |
| --- | --- | --- |
| RDAP / Team Cymru | 注册国 vs 使用国 → 原生/广播 IP | 免费 |
| ip-api.com | 国家、ASN、`hosting`、`proxy` | 免费，**项目已用** |
| ipwho.is | 地理信息第二来源 | 免费 |
| Shodan InternetDB | 开放端口、tags、漏洞、CVE | **免费无 key**，已实测 |
| DNSBL × 8 | Spamhaus / SpamCop / PSBL / blocklist.de / UCEPROTECT / s5h / DroneBL / SpamRats | **全部免费**，项目目前**只查了 Spamhaus 一个** |
| proxycheck.io | 代理/VPN 判定 | 免费额度（需 key） |
| AbuseIPDB | 滥用举报 | 免费 1000 次/天（需 key） |
| Tor 出口列表 | 一票否决 | 免费公开列表 |
| 云厂商 IP 段 | 数据中心判定 | 免费公开 JSON |

扣分模型（按其报告口径复刻）：

```
purity = 100
  - 命中代理/VPN          (-20)
  - 命中机房段            (-25)
  - 广播 IP               (-15)
  - 每个 DNSBL 命中       (-10 ~ -20)
  - AbuseIPDB 举报分高    (-10)
  加分：住宅宽带、原生 IP（+10 ~ +15）
  上限：Tor 出口 / Spamhaus 命中时，加分无法抵消
```

**这套自建的额外好处**：可以按我们自己的用途调权重。比如免费节点几乎不可能是住宅 IP，所以「住宅加分」对我们无意义，可以直接去掉；而 AI 场景权重应该给 `proxy`、`is_tor`、`is_hosting` 和 AbuseIPDB。

最大的一笔增量其实很便宜：**把 DNSBL 从一个扩到八个**，只改 `config/filters.yaml` 的 `dnsbl_zones`，代码不用动（[reputation.py](vpnnode/filters/reputation.py) 已是遍历 zones 的实现）。

#### （4）ippure 真正独有、我们复刻不了的信号

**Cloudflare Bot Score**（ippure 显示的「Cloudflare 风控系数 = 100 − Bot Score」）由 Cloudflare 实时返回，需要 CF 企业版能力，公开渠道拿不到。它最接近「AI 平台是否把你当机器人」，但它衡量的是**自动化流量特征**，不是 IP 本身脏不脏，且对公开代理的宽容度反而较高。

#### （5）推荐组合

| 层 | 手段 | 覆盖范围 | 成本 |
| --- | --- | --- | --- |
| 粗筛 | 自建评分（8 个 DNSBL + ip-api + Shodan InternetDB + 原生性） | 全量节点 | 免费 |
| 复核 | ipure.dev key（100 次/天） | 终选几十个 | 免费额度内 |
| 终判 | 经节点真实请求 AI 站点（3.3 的 L3） | 终选节点 | 免费 |

**第三方评分只能做粗筛，不能替代实测。** ipure.dev 自己的报告也承认三个盲区：公开数据源没命中 ≠ 平台没记录；看不出是否独享出口；看不到账号与设备指纹。所以最终「AI 能不能用」还是得靠实测。

---

## 4. 能力三：节点分级打标

### 4.1 为什么不能合成一个等级

「安全」「AI 可用」「快」是**三个独立轴**，用户的诉求场景不同：

- 上 ChatGPT/Claude → 要 AI 可用 + 稳定，慢一点也能忍
- 日常刷网页 → 要快，AI 干净与否无所谓
- 敏感场景 → 要安全（证书有效、无明文、非公开滥用 IP）

合成一个 A/B/C 等级必然丢信息。正确设计是**每个轴独立评级 + 按用途组合分组**。

### 4.2 四个轴的评级

| 轴 | 数据来源 | 等级 |
| --- | --- | --- |
| 安全 | TLS 有效、加密强度、DNSBL、`skip-cert-verify`、ip-api `proxy` | 🟢 安全 / 🟡 存疑 / 🔴 不安全 |
| AI 干净度 | 3.5 的评分 | 🤖✅ / 🤖⚠️ / 🤖❌ / ☁️ CDN |
| 速度 | 真实请求延迟分档 | ⚡ 快 <300ms / 🚀 中 300–800ms / 🐢 慢 >800ms |
| IP 类型 | 出口 IP 情报 | 🏠 住宅 / 🏢 数据中心 / 📡 移动 / ☁️ CDN |

### 4.3 输出形态

**（1）节点名带标签**

```
🇯🇵 东京 01 | 🟢安全 🤖✅ ⚡312ms
```

`assign_display_names()` 已经统一改名，在这里拼接标签即可。注意 Clash 客户端对节点名长度敏感，建议**最多 2 个标签**，其余放 `nodes.json`。

**（2）按用途分组（`renderers/clash.py` 的 `_build_groups`）**

| 分组 | 成员 | 用途 |
| --- | --- | --- |
| 🚀 自动 | 全部（url-test 按延迟） | 默认 |
| 🤖 AI 优选 | AI 干净 + 安全 | ChatGPT/Claude |
| 🏠 住宅 IP | ip_type=residential | 需要原生 IP 的站点 |
| 🟢 安全 | 安全等级=🟢 | 敏感场景 |
| ⚡ 低延迟 | 速度=⚡ | 日常 |
| ♻️ 手动 | 全部 | 兜底 |
| 🌍 国家组 | 现有按国家分组 | 保留，改为只收 安全≠🔴 的节点 |

**（3）新增 `output/nodes.json`（单节点明细）**

```json
{
  "name": "🇯🇵 东京 01",
  "protocol": "trojan",
  "server": "x.x.x.x",
  "exit_ip": "1.2.3.4",
  "country": "JP",
  "asn": "AS4766",
  "ip_type": "datacenter",
  "proxy_flag": false,
  "dnsbl": false,
  "tls_ok": true,
  "latency_ms": 312,
  "ai": {"chatgpt": "ok", "openai_api": 401, "claude": "ok", "score": 86},
  "tags": ["🟢安全", "🤖✅", "⚡"],
  "source": "github:..."
}
```

给客户端和对外订阅用 `clash.yaml`/`sub.base64`；`nodes.json` 用于自检和后续分析。

**（4）`report.json` 增加统计块**

```json
"tagging": {
  "safe": 42, "suspicious": 11, "unsafe": 0,
  "ai_clean": 18, "ai_limited": 23, "ai_dead": 30, "cdn_relay": 15,
  "fast": 12, "medium": 40, "slow": 20,
  "residential": 3, "datacenter": 60, "mobile": 2
}
```

配合已有的 `history.jsonl`，可以画出「AI 干净节点数」的日趋势 —— 这才是这个项目长期可看的数据。

### 4.4 挂载点（改动边界）

| 文件 | 改动 |
| --- | --- |
| `filters/exit_ip.py`（新） | 出口 IP 探测 + AI 站点探测，返回 `dict[fingerprint, ExitInfo]` |
| `filters/intel.py`（新） | ip-api 批量查询 + 分级评分（可复用 reputation 的 batch 逻辑） |
| `filters/alive.py` | `build_config` 增加 `listeners`；探测复用同一实例 |
| `renderers/clash.py` | `_build_groups` 增加新分组；节点名拼标签 |
| `pipeline.py` | alive 之后插入 exit/AI 阶段；输出 `nodes.json` |
| `models.py` | 不必改，用 `params` 挂私有键 |
| `config/filters.yaml` | 新增 `ai_probe` / `tagging` 段 |

不动：`precheck`、`probe`、`quality` 的现有语义保持不变，新阶段挂在 `alive` 之后、`quality` 之前（这样被淘汰的节点不必做贵的 AI 探测）。

---

## 5. 实施路线（建议分四期，每期可独立上线）

| 期 | 内容 | 产出 | 预估 |
| --- | --- | --- | --- |
| P1 | Telegram 扩源 + 频道筛选 | 新源进入流水线，`report` 可见产出 | 半天 |
| P2 | 出口 IP 探测（listeners 方案） | 每个节点有 `exit_ip` / `ip_type`，修掉 CDN 入口误判 | 1 天 |
| P3 | IP 情报增强 + 安全分级 + 分组输出 | `nodes.json`、新分组、`report.tagging` | 1 天 |
| P4（可选） | AI 站点探测 + 评分 | 🤖 标签与 AI 优选组 | 1–2 天 |
| P5（可选） | 吞吐测速 | ⚡ 标签从「延迟」升级为「带宽」 | 1 天 |

**建议先把 P1+P2 做掉**：Telegram 扩源成本低，出口 IP 探测是整个分级体系的地基（没有它，后面所有 IP 判定都不准）。P4 的不确定性最高（TLS 指纹、CF 风控、URL 语义漂移），建议最后做，且第一版只做「粗测 + 降级模式」。

---

## 6. 配置草案汇总

```yaml
# config/filters.yaml 新增
ip_intel:
  provider: ip-api          # 复用现有 batch 接口，免费版实测已返回 proxy/hosting
  fields: [countryCode, country, hosting, proxy, mobile, as]
  shodan_internetdb: true   # 免费无 key，取 ports/tags/vulns
  abuseipdb_key: ""         # 可选，免费 1000 次/天
  ipure_key: ""             # 可选，ipure.dev 100 次/天，仅用于终选复核
  ipure_only_for_final: true

# 下面这条是当前性价比最高的改动：项目现在只查 1 个 DNSBL，扩到 8 个只改配置
dnsbl_zones:
  - zen.spamhaus.org
  - bl.spamcop.net
  - psbl.surriel.com
  - bl.blocklist.de
  - dnsbl-1.uceprotect.net
  - all.s5h.net
  - dnsbl.dronebl.org
  - bl.spamrats.com

exit_probe:
  enabled: true
  trace_url: https://www.cloudflare.com/cdn-cgi/trace
  batch_size: 50            # 每批开多少 listener
  timeout_ms: 5000
  concurrency: 30

ai_probe:
  enabled: true
  mode: full                # full | ip_only（CI 装不了 curl_cffi 时降级）
  targets:
    chatgpt:     {url: "https://chatgpt.com/cdn-cgi/trace",  healthy: [200]}
    openai_api:  {url: "https://api.openai.com/v1/models",   healthy: [401]}
    claude:      {url: "https://claude.ai/cdn-cgi/trace",    healthy: [200]}
    anthropic_api:{url: "https://api.anthropic.com/v1/models", healthy: [401]}
  timeout_ms: 5000

tagging:
  latency_fast_ms: 300
  latency_slow_ms: 800
  name_max_tags: 2
  groups:
    ai: true
    residential: true
    safe: true
    fast: true
```

---

## 7. 风险清单

| 风险 | 影响 | 缓解 |
| --- | --- | --- |
| Cloudflare 因 TLS 指纹误判 403 | AI 可用性大面积误报 | 用 `curl_cffi` 模拟 Chrome；或降级为「只信 IP 情报」并在报告注明 |
| 401/403 语义随 URL 版本漂移 | 判定失效 | 不写死状态码，按同批次众数 + 是否出现 challenge 页面判定 |
| CDN 中转节点的出口不可见 | IP 类型误判 | 单独标记 `☁️ CDN`，不参与住宅/数据中心评级 |
| ip-api 免费 45 rpm / batch 15 rpm | 查询被限流 | 复用现有分批 + sleep；出口 IP 去重后查询；超限记录 `ip_intel: throttled` |
| CI 30 分钟超时 | 任务失败、订阅不更新 | 新阶段硬超时 + 并发上限；超时降级跳过 AI 阶段而不是整单失败 |
| Telegram 频道失效/删号 | 源产出为 0 | 按产出自动淘汰；`empty preview` 单独计失败原因 |
| 给节点名加 emoji 标签导致客户端兼容问题 | 导入报错 | 标签限 2 个、避免特殊分隔符；`nodes.json` 存完整信息 |
| 出口 IP 探测消耗节点流量 | 免费节点可能限速/断流 | 每节点只请求 trace（约几 KB），不做大文件下载 |

---

## 8. 明确不做的

- **不做端到端「偷流量」检测**：需要中间人解密，不具备可行性，README 已声明这一边界。
- **不做国内网络可达性测试**：Actions 在境外，测不出国内墙况（现有边界不变）。
- **第一版不做 AI 对话级验证**（发真实 prompt）：需要账号，违法与被封风险高，且成本远超收益。
- **不改 `quality` 的限额逻辑**：新标签只影响分组和展示，不改变入选规则，避免一次性改动过大。

---

## 9. 验收标准

| 期 | 验收 |
| --- | --- |
| P1 | CI 跑完后 `fetched_by_source` 有 `telegram:*` 条目且 > 0；失效频道能被识别 |
| P2 | 对同一节点，出口 IP 与 `server` 解析 IP 不同的节点占比可看到（说明 CDN 中转被识别）；抽样人工核对 |
| P3 | `nodes.json` 字段齐全；`clash.yaml` 可被 mihomo 正常加载；分组数量与报告统计一致 |
| P4 | AI 优选组的节点手工在浏览器验证 ChatGPT/Claude 可用率 > 80% |

---

## 10. 实施进度

### 已完成（2026-11-24）

#### P1 Telegram 扩源

- `sources/common.py` 新增 `strip_html()`：删标签而非替换空白，能把被 span 拆断的 URI 接回去；剥离 script/style；还原 `&amp;`。
- `sources/telegram.py` 支持 `channels` 列表与 `?before=` 翻页，带最小 id 锚点防止死循环。
- `config/sources.yaml` 启用 telegram 源，当前只配 `freenodedaily`（唯一实测有内容的频道）。
- 测试：`tests/test_telegram.py` 9 项。

#### P2 出口 IP 探测

- `filters/exit_probe.py`（新）：`parse_trace()` 解析 cloudflare trace；`probe_exit()` 经本地 mixed 端口请求。
- `filters/alive.py`：`build_config()` 支持 `listen_base_port`，为每个节点生成 `listeners` 条目（`proxy` 钉死出口）；`_probe_exits()` 在 alive 成功后回填 `exit_ip/exit_loc/warp`；内核拒绝整批时降级重试不再挂 listeners。
- `pipeline.py`：出口信息写入 `node.params`，`report.stats.alive` 增加 `exit_resolved`。
- 配置：`exit_probe` / `exit_probe_timeout_ms` / `exit_probe_concurrency`。

**真实内核验证**：mihomo v1.19.34 用 `build_config` 生成的配置启动成功，`17890/19090/20000/20001` 四个端口全部监听在 `127.0.0.1`，证明 `listeners.proxy` 字段可用。

#### P3 分级打标

- `filters/intel.py`（新）：`classify_ip`（cdn/mobile/datacenter/residential）、`safety_level`、`latency_level`、`ip_score`、`apply_tags`；`apply_intel` 按**出口 IP** 查 ip-api 与 DNSBL，给节点打标。
- `pipeline.py`：quality 之后执行 intel，输出 `output/nodes.json`，`report.stats.tagging` 记录分布。
- `renderers/clash.py`：新增 `🏠 住宅 IP` / `🟢 安全` / `⚡ 低延迟` 三个按用途分组，空组不输出；节点名追加最多两个标签。
- 配置：`intel_enabled`、`latency_fast_ms`、`latency_slow_ms`、`intel_batch_size`、`intel_dnsbl_zones`（8 个）。

两个实现要点：

1. **DNSBL 分成两套**：`dnsbl_zones` 查入口 IP 用于剔除（保持单 zone，控制全量查询成本）；`intel_dnsbl_zones` 查出口 IP 用于打标（8 个 zone，只查存活节点，量级小）。
2. **修掉一个静默 bug**：`_query_ip_api` 原本的 fields 不含 `proxy`/`mobile`，intel 读到的 `proxy` 恒为 `False`，风险分失真。已补字段并加回归测试。

**真实验证**：`8.8.8.8` → datacenter / proxy+hosting → score 35；Cloudflare 段 `104.16.132.229` → cdn / score 75。

### 待做

| 期 | 内容 | 状态 |
| --- | --- | --- |
| P4 | AI 站点探测（需定 TLS 指纹方案：`curl_cffi` vs 降级为仅 IP 情报） | 未开始 |
| P5 | 吞吐测速（可选） | 未开始 |

Shodan InternetDB 暂未接入：它返回的开放端口/漏洞对「IP 干不干净」帮助有限，先不增加请求量。

## 参考资料

- [ChatGPT「Unusual activity」触发原因与 IP 风控自查](https://ip.net.coffee/gpt/identity.html)
- [2026 出海 AI 大模型防封号网络指南：节点风控等级判定](https://jiasuqijichangtuijian.blog/article/chatgpt-claude-ip-risk-control-and-proxy-guide/)
- [ChatGPT & Claude 代理下的 Verify-You-Are-Human 循环](https://clashverges.org/en/blog/ai-web-human-verification-loop/)
- [mihomo 入站配置（listeners 的 proxy 字段）](https://github.com/metacubex/meta-docs/blob/0ec4dad4496d905b42db3794c49b2ce690a13a5b/docs/config/inbound/index.md)
- [ip-api.com 免费额度（45 rpm / batch 15 rpm）](https://freetier.co/directory/products/ip-apicom)
- [ipapi.is 免费额度与风险字段](https://ipapi.is/)
- [IPPure FAQ：风险系数与 Cloudflare 系数的定义](https://ippure.com/faq)
- [ipure.dev API 文档（公开接口与配额）](https://ipure.dev/docs/api)
- [ipure.dev：原生 IP 与广播 IP 的判定方式](https://ipure.dev/concepts/native-vs-broadcast)
- [Shodan InternetDB（免费无 key）](https://internetdb.shodan.io/)
