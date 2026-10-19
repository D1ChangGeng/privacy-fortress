# 代理分流与 DNS 架构

分流规则的完整设计（五相位、探测对抗、两种部署形态）见 `network-gateway.md`，本文只保留 DNS 架构、住宅 IP 选购、GUI 客户端文件注入约束。事故与决策见 `lessons.md`，事故恢复顺序见 `ops-runbook.md`，killswitch 见 `killswitch.md`。

## §1 DNS 三层设计（2026-10-19 定版）

```
dns:
  enable: true
  listen: "0.0.0.0:1053"        # 客户端内部端口，按客户端调整
  ipv6: false                   # 层1: 关 AAAA
  enhanced-mode: "fake-ip"      # 层2: fake-ip
  default-nameserver: ["<国内DNS IP>"]          # 引导解析(仅用于解析DoH域名/IP, IP字面量时无消耗)
  nameserver: ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]  # 层3: 境外域名DoH
  nameserver-policy:
    "geosite:cn": ["<国内DNS IP>"]              # 层4: 国内域名国内解析(国内人设, 可用性折衷)
tun:
  dns-hijack: ["any:53"]        # 所有 53 端口流量强灌进核心, 无旁路
```

要点：

- **DoH-over-proxy 是架构核心**：非 CN 域名一律由核心经 DoH(443) 解析，DoH 连接本身走规则管线落隧道出口——境外域名的每一跳（核心→DoH→权威）都在境外。用 **IP 字面量** 端点，引导查询为零，不依赖任何域名解析。
- **为什么必须如此**：明文 UDP 53 在不可信本地网上没有任何目的地可言——本地网关设备（高校/酒店/企业网常见的 Panabit 类）会整体劫持 53 端口代答，无论你的查询目标是哪个公共 DNS；上游变成当地运营商递归，境外浏览记录暴露且应答可被投毒（实战：`www.google.com` 被解析到 Facebook 的 IP）。检测方法：ipleak dnsdetection 官方 API 脚本化（每日巡检已固化此哨兵）。
- **国内域名的暴露面是有意识的折衷**：geosite:cn 走国内 DNS 直连，本地网看到"解析了淘宝/百度"与国内人设一致。若国内 DNS 也被本地网投毒，可全量改国内 DoH（如 `https://223.5.5.5/dns-query`）。
- **引导防自锁**：节点域名解析用 `proxy-server-nameserver`（国内 DNS IP 字面量）+ `IP-CIDR,<国内DNS IP>/32,DIRECT,no-resolve` 规则；即使隧道全死，核心仍能解析节点域名完成恢复。no-resolve 防止 fake-ip 把 DNS 服务器自身也劫持造成死循环。
- **DoH 硬化**：`doh.pub`/`alidns.com` 等 DoH 端点域名规则一律指向代理组——应用硬编码偷跑 DoH 时，要么拿到出口地应答，要么超时回落系统 DNS（=干净管线）。核心自身用 IP 字面量，不依赖这些域名。
- **fake-ip-filter 白名单**：校园网/企业认证页、QQ 快速登录、STUN、系统连通性探测等必须拿真 IP 的域放行进真解析（否则这些功能坏），其余全部 fake-ip。

## §2 住宅 IP 选购标准

| 指标 | 达标线 | 检测站 |
|---|---|---|
| 类型 | 真住宅/家宽 ASN（非 DC/广播段） | iplark C 段画像 |
| AI 检测 | 尽量"检测失败"（无法判定人机） | iplark |
| 代理检测 | "检测失败"或普通住宅 | iplark / scamalytics |
| 欺诈分 | 低分（Fraud Score 低） | scamalytics |
| 人机占比 | 人类流量占比高 | ippure |
| 目标服务可用性 | 能过 Cloudflare 校验、不被目标 AI 服务 403 | ip.net.coffee/cloudflare、实测登录 |
| DNS 环境 | 本地网不劫持 UDP53（选购前先测，见 §1） | ipleak dnsdetection |

注意：IP 库城市级定位经常错（同一 IP 被标为相邻城市），省份/国家级才可靠。选购以 ASN 与欺诈分为主要判据，城市标签仅参考。独享优于共享；共享 IP 问清并发用户数与段内其他用户行为风险。

作者实测在用的服务（长期稳定，可作基准参照）：

- 中转 VPS：自选机房（近本地入口、不限流量、协议抗干扰）
- 住宅 IP：[IPDEEP](https://www.ipdeep.cn/?extendid=821fNWE0ODI3MzA2OTM4MzAxMTUzMzUx)——真家宽段，本 skill 巡检基线 IP 即出自该服务
- 机场/链式代理（GUI 客户端形态基准）：[蜂窝加速器](https://share.fengwo.live#/register?code=yxRGajMF)——支持链式代理与 TUN 全局接管

## §3 GUI 客户端的既定约束（文件注入与存储模型）

文件级注入配置的存活前提：只改客户端**已识别的白名单配置键**。客户端把配置保存在强类型内存模型中，每次启动从内存态整体覆写配置文件——未识别的键、非白名单取值一律丢弃。实验判定法：写入 → 重启客户端 → 读生成配置核验，三次重启存活才算数。`geosite:cn` 这类客户端预置键、DoH nameserver 取值已被多个客户端接受；其余键按此实验法逐个验证。

**存储真源模型**（FlClash 系实测）：界面状态在内部存储（`database.sqlite` 的 rules + profile_rule_mapping 表，`scene=added/disabled` 软删除，`order` 为 fractional indexing 字符串），链式代理在 prefs 的 `chainProxies` + `activeChainProxyName`，端口/系统代理/TUN/IPv6 在 vpnProps/networkProps；`config.yaml` 是生成物——版本升级/存储迁移时客户端从内部存储重建，文件直改全部蒸发（实战两次：链式节点被删+规则回滚）。**对这类客户端：一切编辑走 UI 编辑器，改真源不改生成物；DB 直改只对"修改 UI 已建行的既有字段"可靠——手工 INSERT 的新规则行即使字段完全一致也不被 UI 通道消费（静默忽略）。** 升级前备份三件套（内部数据库/prefs/生成配置，带时间戳）；恢复=新状态上重放手术，不整体回退。端口跟随客户端（升级可能改混合端口），自建工具的代理引用（git config/脚本/环境变量）同步改。

**IPv6 双关口径**：核心 IPv6 与 DNS IPv6 都要 false——住宅链一般仅 IPv4，核心 v6 开着等于留一条未经验证的出口。

## §4 旧转发器方案存档

~~`scripts/dns-forwarder.py`（127.0.0.1:53 → DoH，核心 nameserver 首查回环）已退役~~：多一跳本地组件、回环 53 单端口在部分客户端被拒、无消费者。现役设计为 §1 的 DoH-over-proxy。脚本存档供无法接受 DoH nameserver 的旧客户端形态参考。

## §5 已迁出内容索引

- 分流规则五相位 / 探测对抗 / 自建与 GUI 部署形态 → `network-gateway.md`
- killswitch 桌面端 + 浏览器变体 → `killswitch.md`
- 巡检 / 台账 / 回退 / 事故恢复 / 升级四键 / 双开处置 → `ops-runbook.md`
