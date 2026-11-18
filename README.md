# VPN 节点爬虫

每天从公开渠道抓取节点，按四层规则过滤，输出 Clash/Mihomo YAML 与 Base64 订阅。

设计文档见 [docs/2026-11-18-vpn-node-crawler-design.md](docs/2026-11-18-vpn-node-crawler-design.md)。

## 能力边界

- 能排除：明文代理、关闭证书校验、自签/无效证书、内网地址指向、Clash 脚本注入字段、弱加密、DNSBL 黑名单、连不通或握手过慢
- 不能证明：节点“不偷流量”；劫持行为只有实际使用才暴露
- reality 节点无证书可校验，仅做 TCP 探测
- 测速交给客户端（`url-test` 指向 `gstatic/generate_204`），爬虫不测带宽

在中国大陆使用未经批准的跨境 VPN 属于违规行为，本项目只做公开数据的抓取与格式转换，使用风险自负。

## 本地运行

数据源同时启用官方 raw 源（Actions 中可达、节点最新）与 jsDelivr 镜像（国内网络可直连，文件有缓存、可能滞后）。重复节点在去重阶段会被合并。

```bash
cd VPN
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements-dev.txt

# 离线验证：解析测试样本，跳过联网探测
.venv/Scripts/python.exe -m vpnnode.pipeline \
  --offline tests/fixtures --out output \
  --no-probe --no-reputation --no-upload --min-nodes 0

# 在线运行（GitHub/Telegram 源需要代理）
HTTPS_PROXY=http://127.0.0.1:7890 HTTP_PROXY=http://127.0.0.1:7890 \
.venv/Scripts/python.exe -m vpnnode.pipeline --out output --no-upload
```

输出：

- `output/clash.yaml` — 直接导入 Clash Verge / Mihomo
- `output/sub.base64` — v2rayN / v2rayNG 订阅
- `output/report.json` — 每层过滤的漏斗统计与被剔除原因

## 配置

| 文件 | 说明 |
| --- | --- |
| `config/sources.yaml` | 数据源清单：`github` / `webpage` / `subscription` / `telegram` |
| `config/filters.yaml` | `tls_policy`（strict/loose）、并发、超时、限额等 |

`tls_policy: strict` 会剔除自签证书节点；免费节点淘汰率高时改成 `loose`（保留但打 `self_signed` 标记）。

## 测试

```bash
.venv/Scripts/python.exe -m pytest -q
```

## 定时任务与订阅（GitHub Actions + jsDelivr）

`.github/workflows/daily.yml` 每天北京时间 05:17 自动运行：抓取、过滤，把结果提交回仓库的 `output/`，然后主动清除 jsDelivr 缓存。

订阅地址（固定不变）：

```text
https://fastly.jsdelivr.net/gh/Berlinye555/vpn-node-crawler@main/output/clash.yaml   # Clash
https://fastly.jsdelivr.net/gh/Berlinye555/vpn-node-crawler@main/output/sub.base64   # v2rayN
```

注意事项：

- 仓库必须保持**公开**，jsDelivr 只能读取公开仓库
- 节点列表因此对所有访问者可见（节点本身来自公开渠道）
- jsDelivr 对分支引用有缓存，workflow 每次运行后会调用 purge 接口刷新；若更新仍有延迟，手动打开 `https://purge.jsdelivr.net/gh/Berlinye555/vpn-node-crawler@main/output/clash.yaml` 即可清除

### 可选：私密订阅（Cloudflare Worker）

如果不想公开节点，`worker/` 目录提供私有订阅方案（KV 存储 + 带密钥 URL），部署说明见 [worker/wrangler.toml](worker/wrangler.toml) 注释。注意 `workers.dev` 在国内不稳定，通常需要绑定自定义域名才可靠。
