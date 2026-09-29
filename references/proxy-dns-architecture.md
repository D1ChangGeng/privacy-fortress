# 代理分流与 DNS 架构

## 目录
- [§1 分流规则设计](#1-分流规则设计)
- [§2 DNS 五层设计](#2-dns-五层设计)
- [§3 住宅 IP 选购标准](#3-住宅-ip-选购标准)
- [§4 转发器部署](#4-转发器部署)
- [§5 Clash 系客户端的既定约束](#5-clash-系客户端的既定约束)
- [§6 事故恢复顺序](#6-事故恢复顺序)

## §1 分流规则设计

适用任何 Clash/Mihomo 兼容客户端。规则自上而下首命中即停，最终形态：

```
1. REJECT 纯遥测域名（ sentry.io / datadoghq.com / oaistatsig.com /
   copilot 遥测 collector / exp-tas 等，清单见 browser-telemetry.md §2 ）
2. 进程白名单 DIRECT（日常国内应用，逐进程标注用途）
3. 链式目标域名组（国外 AI/开发/云服务域名 → 代理组）
4. 国内域名白名单 DIRECT（日常真用服务，最小化）
5. IP 白名单 DIRECT（引导解析 DNS IP + 内网/认证系统，每条标注归属）
6. DoH 端点域名（国内外全部 → 代理组，封死应用偷跑 DoH 的直连通道）
7. MATCH → 代理组（兜底，绝不允许直连兜底）
```

铁律：
- **match 类规则全部位于兜底 MATCH 之前**；兜底必须是最后一个有效规则。
- 国外 AI 应用访问国内站点（未被白名单命中的）自动落兜底走出口——这是"国际化"设计的核心收益，不要在客户端里给国内大站配直连。
- 进程规则在 TUN 模式下进程识别仍然有效（实测），优先用进程规则保护"必须直连才能活"的应用（如本机 AI 客户端本体）。
- 链式代理的目标组书写：一律写底层单跳组名，由客户端自动升级链式；直接写链式组名会被物化成嵌套封装组。
- 客户端 UI 可见的规则与数据库/生成配置可能不一致：数据库存在而生成配置未渲染的行（同规则启用/停用双行、跨 profile 行）会造成"UI 里有、实际不生效"。审计时以**生成的 yaml 配置**为准，不以 UI 或数据库行数为准。
- 订阅自带的大规则集若排在 MATCH 之后即为死代码（MATCH 之后一切不生效），无需清理但要知道它在不在生效面内。

## §2 DNS 五层设计

```
dns:
  enable: true
  listen: "0.0.0.0:1053"        # 客户端内部端口，按客户端调整
  ipv6: false                   # 层1: 关 AAAA
  enhanced-mode: "fake-ip"      # 层2: fake-ip
  nameserver: ["127.0.0.1"]     # 层3: 首查本地转发器(53)
  proxy-server-nameserver: ["<国内DNS IP>"]   # 层4: 节点引导解析, IP字面量
  fallback: ["tls://1.1.1.1", "tls://8.8.4.4"]  # 经 respect-rules 走代理
  nameserver-policy:
    geosite:cn: "<国内DNS IP>"   # 层5: 国内域名国内解析(可用性折衷)
tun:
  dns-hijack: ["any:53"]        # 所有 53 端口流量强灌进核心, 无旁路
```

要点：
- **转发器是架构核心**：核心首查 127.0.0.1:53 → `scripts/dns-forwarder.py` → DoH 1.1.1.1 → 流量经 TUN 落兜底 MATCH 走隧道出口。境外查询的每一跳都在境外。回环流量不入 TUN、不被 hijack 拦截，无循环。
- **韧性**：转发器上游失败时回 SERVFAIL，核心自动回落国内 DNS——联网不断，查询面降级。巡检将其标 FAIL 提示降级状态。
- **DoH 硬化**：`doh.pub`/`alidns.com` 等国内外 DoH 端点域名规则一律指向代理组。规则引擎分不清"核心的引导 DoH"和"应用偷跑的 DoH"，所以整个端点压进隧道：偷跑探测要么拿到出口地应答，要么超时回落系统 DNS（=干净管线）。核心自身的引导解析改用 IP 字面量，不依赖这些域名。
- **引导防自锁**：`proxy-server-nameserver` 用 IP 字面量 + 一条 `IP-CIDR,<国内DNS IP>/32,DIRECT,no-resolve` 规则。即使隧道全死，核心仍能解析出节点域名完成恢复。no-resolve 防止 fake-ip 把 DNS 服务器自身也劫持造成死循环。

## §3 住宅 IP 选购标准

| 指标 | 达标线 | 检测站 |
|---|---|---|
| 类型 | 真住宅/家宽 ASN（非 DC/广播段） | iplark C 段画像 |
| AI 检测 | 尽量"检测失败"（无法判定人机） | iplark |
| 代理检测 | "检测失败"或普通住宅 | iplark / scamalytics |
| 欺诈分 | 低分（Fraud Score 低） | scamalytics |
| 人机占比 | 人类流量占比高 | ippure |
| 目标服务可用性 | 能过 Cloudflare 校验、不被目标 AI 服务 403 | ip.net.coffee/cloudflare、实测登录 |
| DNS 解析 | 该 IP 支持公共 DNS 正常解析（部分住宅 IP 的 DNS 被污染或不响应，买来先测） | nslookup 实测 |

注意：IP 库城市级定位经常错（同一 IP 被标为相邻城市），省份/国家级才可靠。选购时以 ASN 与欺诈分为主要判据，城市标签仅参考。独享优于共享；共享 IP 要问清并发用户数与段内其他用户行为风险。

作者实测在用的服务（长期稳定，可作基准参照）：

- 机场/链式代理：[蜂窝加速器](https://share.fengwo.live#/register?code=yxRGajMF)——支持链式代理与 TUN 全局接管，本 skill 的全部网络层设计在其上验证
- 住宅 IP：[IPDEEP](https://www.ipdeep.cn/?extendid=821fNWE0ODI3MzA2OTM4MzAxMTUzMzUx)——真家宽段，本 skill 巡检基线 IP 即出自该服务

## §4 转发器部署

1. 复制 `scripts/dns-forwarder.py` 到常驻目录（如 `<workspace>/guard/`）。
2. 客户端 nameserver 首查改为 `127.0.0.1`（见 §2），`dns-hijack: any:53`。
3. 开机自启：Startup 文件夹放 vbs，`pythonw.exe` 无窗口启动：
   ```vb
   Set ws = CreateObject("WScript.Shell")
   ws.Run """<pythonw路径>"" ""<dns-forwarder.py路径>""", 0, False
   ```
4. 验证：查询一个全新域名 → 抓包/连接日志可见转发器→DoH 443 连接；杀转发器后 curl 仍 200（回落韧性）；重启后 127.0.0.1:53 LISTENING。

## §5 Clash 系客户端的既定约束

文件级注入配置的存活前提：只改客户端**已识别的白名单配置键**。客户端把配置保存在强类型内存模型中，每次启动从内存态整体覆写配置文件——未识别的键、非白名单取值一律丢弃。实验判定法：写入 → 重启客户端 → 读生成配置核验，三次重启存活才算数。`geosite:cn` 这类客户端预置键、loopback 形式的 nameserver 值已被多个客户端接受；其余键按此实验法逐个验证。

## §6 事故恢复顺序

改 DNS/分流配置后失联时，按序执行，每步后实测联网：
1. 关链式代理（若启用）。
2. 关 TUN，退回系统代理模式。
3. 核验 nameserver 是否被客户端覆写漂移。
4. 仍不通：重启客户端；再不通：用最近一份备份恢复配置库后重启。
验收基线：用户本机正在使用的 AI 客户端能在 TUN 下正常对话 = 网络层验收通过的最高优先级项。
