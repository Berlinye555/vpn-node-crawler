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

# 在线运行（本地 raw 源不可达时需要代理）。在线模式必须带 mihomo：
# 没有真实测试的节点不发布；仅调试可用 --allow-unverified 跳过
HTTPS_PROXY=http://127.0.0.1:7890 HTTP_PROXY=http://127.0.0.1:7890 \
.venv/Scripts/python.exe -m vpnnode.pipeline --out output --no-upload --mihomo ./mihomo

# 有 mihomo 内核时追加真实请求验证
.venv/Scripts/python.exe -m vpnnode.pipeline --out output --no-upload --mihomo ./mihomo
```

数据源默认只配 raw 地址（Actions 环境可达）。本地调试若 raw 不可达，可临时把某条改成 `https://fastly.jsdelivr.net/gh/{owner}/{repo}@{branch}/{path}`，不要长期启用（会重复抓取）。

输出：

- `output/clash.yaml` — 直接导入 Clash Verge / Mihomo；节点名带分级标签，含 `🏠 住宅 IP` / `🟢 安全` / `⚡ 低延迟` 等用途分组
  - `🚀 自动` 只收**抗封锁协议**（TLS / REALITY / hysteria2 / trojan / 带 TLS 的 ws、grpc）
  - `📦 全部节点` 含明文 SS 等全部节点；`♻️ 手动` 可自选
- `output/sub.base64` — v2rayN / v2rayNG 订阅
- `output/nodes.json` — 单节点明细：出口 IP、ASN、IP 类型、安全等级、延迟、`ip_score`、`resistant` 标记
- `output/report.json` — 漏斗统计、分阶段耗时、每源抓取数与最终贡献、被剔除原因、分级分布

> 为什么自动组要过滤：明文 SS/VLESS 在境外测全通、境内必被墙（GFW 按流量特征识别）。CI 跑在境外机房，测不出这一点，所以改为按协议判定而不是实测。抗封锁节点不足 10 个时自动组回退为全部节点。

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

`exit_probe: true` 会在 alive 之后**单独起一台内核**，只给存活节点各开一个本地端口，经端口请求 `cloudflare/cdn-cgi/trace` 记录真实出口 IP —— CDN 中转节点的 `server` 解析地址是入口，不等于出口。结果写入 `node.params.exit_ip` 与 `report.stats.exit_probe`。

> 出口探测不能挂在 alive 阶段：alive 面对的是全量节点（数千个），每节点一个 listener 会让内核起不来；拆开后 listeners 数量只与存活节点数（几十到几百）相关。

`intel_enabled: true` 会在 quality 之后按出口 IP 查 ip-api（国家/ASN/`proxy`/`hosting`）和 `intel_dnsbl_zones` 里的黑名单，给每个节点打安全/速度/IP 类型标签。注意 `dnsbl_zones` 查的是入口 IP（剔除用），`intel_dnsbl_zones` 查的是出口 IP（打标用），两者分开。

> AI 平台可用性探测（P4）评估后**未采用**：探测「API 层没封这个 IP」推不出「网页可用」，且免费节点几乎全是数据中心共享 IP，`clean` 数量趋近于 0。需要判断能否用于 AI 时，看出口 IP 的 `hosting` / `proxy` 标记即可（数据中心 + 代理标记的基本不用指望）。详见设计文档第 10 节。

## 测试

```bash
.venv/Scripts/python.exe -m pytest -q
```

## 本地验证节点可用性

CI 跑在境外机房，只能回答「节点后端是否活着」。**明文协议在境外测全通、境内必被墙**——要确认节点在你自己网络里能不能用，用这个脚本：

```bash
# 需要 mihomo 内核：放到项目根目录，或用 --mihomo / MIHOMO_PATH 指定
python tools/local_check.py --clash output/clash.yaml

# 直接测订阅（支持 base64 / Clash / 明文）
python tools/local_check.py --sub https://gcore.jsdelivr.net/gh/Berlinye555/vpn-node-crawler@main/output/sub.base64

# 只测抗封锁协议，跳过明文 SS
python tools/local_check.py --clash output/clash.yaml --protocols vless,trojan

# 只测前 50 个，超时 3 秒
python tools/local_check.py --clash output/clash.yaml --limit 50 --timeout 3
```

默认目标是 `https://www.google.com/generate_204`（境内需过墙才是真可用）。注意：**测之前关掉其他代理和 TUN**，否则流量被接管，结果失真。脚本开头的自检会提示本机能否直连目标。

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
