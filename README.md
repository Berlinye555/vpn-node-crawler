# VPN 节点爬虫

每天从公开渠道抓取节点，经**五层过滤**（静态安全检查 → TCP/TLS/WS 探测 → IP 信誉 → mihomo 真实请求 → 质量限额）后，输出 Clash/Mihomo YAML 与 Base64 订阅。

设计文档见 [docs/2026-11-18-vpn-node-crawler-design.md](docs/2026-11-18-vpn-node-crawler-design.md)。

## 能力边界

- **能排除**：明文代理、关闭证书校验、私网地址指向、Clash 脚本注入字段、弱加密、废弃 XTLS flow、DNSBL 黑名单、连不通或握手过慢、WS 后端已死的 CDN 中转节点、真实 HTTP 请求失败的节点
- **不能证明**：节点“不偷流量”；reality 节点无证书可校验
- **真实测试跑在境外机房**：筛得出“后端已死”，筛不出“境外能连、国内被墙”
- 测速交给客户端（`url-test` 指向 `gstatic/generate_204`），爬虫不测带宽

在中国大陆使用未经批准的跨境 VPN 属于违规行为，本项目只做公开数据的抓取与格式转换，使用风险自负。

## 本地运行

```bash
cd VPN
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements-dev.txt

# 离线验证：解析测试样本，跳过联网层
.venv/Scripts/python.exe -m vpnnode.pipeline \
  --offline tests/fixtures --out output \
  --no-probe --no-reputation --no-upload --min-nodes 0

# 在线运行（本地 raw 源不可达时需要代理）
HTTPS_PROXY=http://127.0.0.1:7890 HTTP_PROXY=http://127.0.0.1:7890 \
.venv/Scripts/python.exe -m vpnnode.pipeline --out output --no-upload

# 有 mihomo 内核时追加真实请求验证
.venv/Scripts/python.exe -m vpnnode.pipeline --out output --no-upload --mihomo ./mihomo
```

数据源默认只配 raw 地址（Actions 环境可达）。本地调试若 raw 不可达，可临时把某条改成 `https://fastly.jsdelivr.net/gh/{owner}/{repo}@{branch}/{path}`，不要长期启用（会重复抓取）。

输出：

- `output/clash.yaml` — 直接导入 Clash Verge / Mihomo；节点名带分级标签，含 `🏠 住宅 IP` / `🟢 安全` / `⚡ 低延迟` 等用途分组
- `output/sub.base64` — v2rayN / v2rayNG 订阅
- `output/nodes.json` — 单节点明细：出口 IP、ASN、IP 类型、安全等级、延迟、`ip_score`、标签
- `output/report.json` — 漏斗统计、分阶段耗时、每源抓取数与最终贡献、被剔除原因、分级分布

节点分级为三个正交维度，不合成单一等级：

| 维度 | 取值 | 依据 |
| --- | --- | --- |
| 安全 | 🟢 安全 / 🟡 存疑 / 🔴 危险 | 自签证书、跳过校验、出口被标记 proxy/hosting、DNSBL 命中 |
| 速度 | ⚡ 快 / 🐢 慢（300–800ms 不标） | mihomo 真实请求延迟 |
| IP 类型 | 🏠 住宅 / ☁️ CDN / 数据中心 / 移动 | 出口 IP 的 ASN 与 hosting 标记 |

## 配置

| 文件 | 说明 |
| --- | --- |
| `config/sources.yaml` | 数据源清单：`github` / `subscription` / `telegram`（`webpage` 为预留能力） |
| `config/filters.yaml` | TLS 策略、探测并发/超时、限额、DNSBL、alive 采样、出口 IP 探测 |

`tls_policy: strict` 会剔除自签证书节点；免费节点淘汰率高时改成 `loose`（保留但打 `self_signed` 标记）。

`alive_samples` / `alive_min_success_rate` 控制真实请求的成功率阈值；`alive_concurrency` 同时决定专用线程池大小。

Telegram 源抓 `t.me/s/<channel>` 公开预览页，免 token：`channels` 支持多频道，`max_pages` 控制翻页（`?before=`）。首轮跑完看 `report.json` 的 `fetched_by_source`，产出为 0 的频道删掉。

`exit_probe: true` 会在 alive 阶段为每个存活节点开一个独立本地端口，经节点请求 `cloudflare/cdn-cgi/trace` 记录真实出口 IP —— CDN 中转节点的 `server` 解析地址是入口，不等于出口。结果写入 `node.params.exit_ip` 与 `report.stats.alive.exit_resolved`。

`intel_enabled: true` 会在 quality 之后按出口 IP 查 ip-api（国家/ASN/`proxy`/`hosting`）和 `intel_dnsbl_zones` 里的黑名单，给每个节点打安全/速度/IP 类型标签。注意 `dnsbl_zones` 查的是入口 IP（剔除用），`intel_dnsbl_zones` 查的是出口 IP（打标用），两者分开。

`ai_probe_enabled: true` 会经节点请求 OpenAI / Anthropic 的 API 与前端端点，判断能否正常使用 ChatGPT、Claude，通过的节点打 🤖 标签并进入 `🤖 AI 优选` 分组。客户端优先用 `curl_cffi` 模拟 Chrome TLS 指纹；未安装时自动降级 urllib，`report.stats.ai.impersonate` 会标出是否降级。

## 测试

```bash
.venv/Scripts/python.exe -m pytest -q
```

## 定时任务与订阅（GitHub Actions + jsDelivr）

`.github/workflows/daily.yml` 每天北京时间 05:17 自动运行：抓取、过滤、下载 mihomo 做真实测试、把结果提交回 `output/`，然后清除 jsDelivr 缓存。

订阅地址（固定不变）：

```text
https://gcore.jsdelivr.net/gh/Berlinye555/vpn-node-crawler@main/output/clash.yaml   # Clash
https://gcore.jsdelivr.net/gh/Berlinye555/vpn-node-crawler@main/output/sub.base64   # v2rayN
```

备用镜像：把 `gcore.jsdelivr.net` 换成 `testingcf.jsdelivr.net`。`fastly.jsdelivr.net` 缓存滞后明显，`cdn.jsdelivr.net` 国内常不可达。

注意事项：

- 仓库必须保持**公开**，jsDelivr 只能读取公开仓库；节点列表对所有访问者可见
- **jsDelivr 对 `@main` 的分支指针缓存 12 小时，purge 无法清除**：固定地址会滞后。需要立即生效时用 `@<commit-sha>` 地址
- 需要“固定地址 + 实时更新”时，改用对象存储（如腾讯云 COS）或 `worker/` 私密订阅

### 可选：私密订阅（Cloudflare Worker，当前未启用）

`worker/` 目录提供 KV 存储 + 带密钥 URL 的私有方案，部署说明见 [worker/wrangler.toml](worker/wrangler.toml) 注释。注意 `workers.dev` 在国内不稳定，通常需要绑定自定义域名才可靠。
