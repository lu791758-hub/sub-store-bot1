# Sub-Store Bot ☁️

Telegram Bot — 订阅转换 + 短链分享，内置完整 Sub-Store 引擎。

<a href="https://github.com/user-attachments/assets/21b7e05f-5ab4-4198-a6db-215e21739e16"><img src="tools/screenshot1.png" width="120"></a> <a href="tools/screenshot2.png"><img src="tools/screenshot2.png" width="120"></a> <a href="tools/screenshot3.png"><img src="tools/screenshot3.png" width="120"></a>

---

## 功能

| 类别 | 功能 | 说明 |
|------|------|------|
| **输入** | 远程订阅 / 本地订阅 / 多订阅合并 / 反代 | 发 URL 或文件，7 种 UA 轮询拉取（可自定义），PROXY_URL 绕过 CF 拉取拦截，同对话多条自动去重合并 |
| **输出** | 14 种格式 / Snell / 双链 | Clash Meta、URI、JSON、V2Ray、sing-box、Surfboard、QX、Shadowrocket、Surge、Loon、Stash、Egern、Base64；Snell 节点完整支持（Surge 格式 parser 增强）；WG 节点和 Gost 节点独立侧链输出 ;自定义yaml规则集 |
| **YAML 模板** | 仓库模板 + 用户自定义 | 把自己配置清掉 proxies 段丢到 `landing/`（支持 `.ini`/`.yaml`/`.yml`）；编辑 `templates.json`，file 后面填仓库文件名，name 是 bot 显示的，多配置模板英文逗号隔开。设定 `LANDING_DIR` 变量后，bot 内 **同步仓库** 开启 |
| **处理** | 去同名上标 / 智能去重 / 测活 | 同名节点自动上标（²³…），基于 server:port:type:uuid:sni:path:network 特征去重， 测活才用CF原生TCP connect测活 |
| **短链** | 有效期 / 阅后即焚 / 梅开二度 / 管理 | IP 独立计数访问限制，过期/焚毁自动销毁；落地页反向代理可自定义 HTML |
| **安全** | SSRF 防护 / TG 限流 / 配置持久化 / 调试 | SSRF 防护（LANDING_DIR 仅 GitHub）；TG 限流 30s/5 次；Webhook 校验；配置落 KV 升级不丢；DEBUG_TOKEN 鉴权端点 |

---

## 一键部署

点击这个屎黄色按钮
[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Linsars/sub-store-bot)

部署完成后：

1. 去 **域** 页面，打开域名路由或绑定自定义域名（可选）
2. 去 **变量与密钥** 页面，添加环境变量，类型全部选 **密钥** （防止更新被覆盖变量） ：
   - `ALLOWED_USERS` = 白名单ID（可选，逗号分隔），不设则公开使用，也可以只设自己的TGid
   - `BOT_TOKEN` = Telegram Bot Token
   - `PROXY_URL` = 反代地址，绕过 CF 拦截（可选，[搭建教程](landing/proxy-setup.md)）。若反代启用了 token 鉴权，格式为 `https://你的项目名.vercel.app/api?token=你的TOKEN`（bot 会自动补 `url=` 前缀，无需手动拼 `&` 或 `url=`）
   - `LANDING_DIR` = 落地页和模板目录（可选，复制目录页地址删掉 `tree`，如 `https://github.com/Linsars/sub-store-bot/main/landing`）
3. 在 **触发事件** 段，添加 **Cron触发器** 里面的 **计划** 改成 **1** 添加（这一步是给测活用的，如果你不想用测活功能可以不设置）
4. 去 **描述** 页面，复制 Worker 域名并在后面加上webhookbot到浏览器地址栏回车激活 bot如：`https://xxx.workers.dev/webhookbot`
5. Telegram 里发 `/start`

## 环境变量

| 变量 | 说明 | 必填 |
|------|------|------|
| `BOT_TOKEN` | Telegram Bot Token | ✅ |
| `LANDING_DIR` | 落地页和模板目录，默认 `Linsars/sub-store-bot/main/landing` | ❌ |
| `PROXY_URL` | 反代基础 URL，绕过 CF-to-CF 拉取拦截。反代启用鉴权时填 `https://你的项目名.vercel.app/api?token=你的TOKEN`（`url=` 由 bot 自动拼接） | ❌ |
| `ALLOWED_USERS` | 允许的用户 ID（逗号分隔），不设则全部开放 | ❌ |
| `CLIP_URL` | 短链基础 URL（如 `https://xxx.workers.dev`） | ❌ |
| `WEBHOOK_SECRET` | Webhook 请求头校验，防域名探测 | ❌ |
| `DEBUG_TOKEN` | debug-fetch 接口鉴权 Token | ❌ |
| `KV` | KV Namespace 绑定名（一键部署自动创建） | ✅ |


## 目录结构

```
├── worker.mjs              # 主程序
├── proxy-utils.esm.js      # Sub-Store 引擎（构建产物）
├── wrangler.toml           # CF Workers 配置
├── README.md
├── landing/
│   ├── index.html          # 默认落地页
│   ├── templates.json      # YAML 模板清单
│   ├── noom.ini            # NooM 规则集模板
│   └── proxy-setup.md      # 反代搭建教程
├── tools/
│   ├── substorebot-deploy-code.py  # CF 部署脚本（本地用）
│   └── proxy-utils-src/    # 引擎源码 + 构建脚本
│       ├── sync-proxy-utils.js     # 从 sub-store-org/Sub-Store 同步
│       ├── build-proxy-utils.js    # PEG 预编译 + esbuild 打包
│       ├── buffer_shim.js          # Buffer 全局兼容（CF 不支持 import 'buffer'）
│       └── src/                    # Sub-Store 引擎源码
└── .github/
    └── workflows/
        └── sync-proxy-utils.yml    # 引擎自动同步（每周日 6:00 UTC）
```

## Sub-Store 引擎

`proxy-utils.esm.js` 由 `tools/proxy-utils-src/` 从 [`sub-store-org/Sub-Store`](https://github.com/sub-store-org/Sub-Store) 上游同步构建：
- `sync-proxy-utils.js` — 同步 parsers / preprocessors / producers
- `build-proxy-utils.js` — PEG 预编译 + esbuild 打包（`format: esm`，`platform: node`）
- `buffer_shim.js` — `Buffer` 全局兼容（CF Workers 不支导入 `buffer` 模块）
- 工作流 `.github/workflows/sync-proxy-utils.yml` 每周自动运行，也可手动触发

## License

MIT
