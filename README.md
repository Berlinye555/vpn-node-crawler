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

## 定时任务（GitHub Actions）

`.github/workflows/daily.yml` 每天北京时间 05:17 自动运行，支持手动触发。

Actions 在境外机房运行，GitHub raw 与 Telegram 源天然可达。未配置 Worker 密钥时只产出 artifact（保留 7 天）。

## 订阅服务（Cloudflare Worker）

```bash
cd worker
npm install
npx wrangler login
npx wrangler kv namespace create SUBSTORE      # 把返回的 id 填进 wrangler.toml

# 生成两个随机密钥
python -c "import secrets; print('SUB_ACCESS_KEY=' + secrets.token_urlsafe(32))"
python -c "import secrets; print('UPLOAD_TOKEN=' + secrets.token_urlsafe(32))"

npx wrangler secret put SUB_ACCESS_KEY
npx wrangler secret put UPLOAD_TOKEN
npx wrangler deploy
```

然后在 GitHub 仓库 → Settings → Secrets and variables → Actions 添加：

| Secret | 值 |
| --- | --- |
| `WORKER_BASE_URL` | Worker 地址，如 `https://vpn-sub.xxx.workers.dev` |
| `UPLOAD_TOKEN` | Worker 的 `UPLOAD_TOKEN` |
| `SUB_ACCESS_KEY` | Worker 的 `SUB_ACCESS_KEY` |

订阅地址：

```text
https://<worker>/sub/<SUB_ACCESS_KEY>/clash.yaml    # Clash
https://<worker>/sub/<SUB_ACCESS_KEY>/sub.base64    # v2rayN
```

密钥更换后旧链接立即失效。订阅 URL 中的密钥会出现在客户端日志里，建议定期轮换并只用于个人设备。
