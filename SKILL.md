---
name: privacy-fortress
description: 将一台大量泄露真实位置/身份信号的 Windows 电脑改造为最小信息暴露面。覆盖全部信号面：网络出口一致性、DNS 查询面（含本地网关劫持 UDP53 的 DoH-over-proxy 根治）、WebRTC/IPv6 泄漏、系统与硬件指纹（时区/语言/MachineGuid/服务盘点）、软件面与遥测、浏览器指纹与双浏览器分边、账号与 git 元数据、VPN/远控客户端自报家门、本地网络邻近、主动探测面、配置治理（自建裸网关/GUI 客户端存储模型/升级漂移/双开）。包含分阶段施工流程（回退脚本先行+超时自动回退）、五相位分流规则、防火墙 killswitch fail-closed 兜底、每日哨兵巡检、git 历史改写、邮箱第三方暴露审计、能力边界与诚实缺口清单。适用：用户要求"防止应用/web/AI 服务通过多信号综合分析推断我的真实地理位置或身份"、隐私加固、代理+TUN 环境搭建、DNS 防泄漏、住宅 IP 选购、每日隐私巡检、网关运维。不适用于：已构成犯罪的规避执法需求、iOS/Android 设备（本 skill 针对 Windows）。
---

# Privacy Fortress：最小信息暴露面改造

把"每个应用各自裸连、信号散落各处"的电脑，改造为"所有出境流量统一走受控出口、所有信号面要么收敛为掩护身份、要么闭合"的状态。读者不需要看过任何历史会话，按本文件即可执行。

## 五条施工纪律（每条都对应一类已发生的系统级事故，详见 references/lessons.md）

1. **回退先行**：每个阶段动手前，先写该阶段的回退脚本并实测可运行；预估可能断网的步骤，必须设立"超时未确认则自动回退"防线。系统级事故优先级高于一切隐私目标。
2. **温和不破坏联网**：引流（MATCH 到代理）优先于拦截（REJECT）。拦截只用于纯遥测域名。绝不让"默认禁止所有出站"落地。
3. **端到端验收**：每个阶段改完，以"本机日常关键应用仍能联网工作"为最高优先级验收项（AI 客户端/浏览器/通讯工具逐一手动验证）。
4. **改配置先备份**：修改任何配置文件/数据库前，先留时间戳备份；生效路径=备份→修改→重启→核验→实测。
5. **诚实残留**：做不到的面明确记入 references/capability-gaps.md，标注"接受残留"。假装闭合比承认残留更危险。

## 总体架构（最终状态）

```
应用流量
  ├─ REJECT 名单（纯遥测域名）───────────→ 拒绝
  ├─ 白名单进程（国内日常应用）───────────→ 直连（最小化、逐条有身份）
  └─ 其余全部 ──→ TUN 接管 ──→ 五相位规则 ──→ 兜底 MATCH ──→ 链式代理 ──→ 住宅 IP 出口
                                              （系统代理为第二捕获通道, 双开无害）

系统 DNS ──→ 53 端口劫持 ──→ 网关 DNS 模块
                              ├─ 国内域名 → 国内 DNS 直连（国内人设折衷）
                              └─ 境外域名 → DoH(1.1.1.1/8.8.8.8) ──→ 代理链 ──→ 境外应答（全程境外）
```

**fail-closed 哲学**：几乎所有故障形态是"连不上"而不是"悄悄裸连"。宁可暂时打不开网页，不允许不知不觉中泄露。

**权限无关性**：TUN、防火墙、DNS 劫持工作在内核层，应用的管理员权限无法绕过它们。唯一例外是恶意驱动/rootkit——那是"不装来路不明的软件"这条安装纪律的范畴。

掩护身份基线（由用户确认后全机统一）：同一住宅 IP 出口 + 目标国家时区 + 目标国家系统区域 + 浏览器语言指纹一致 + 无 IPv6 出境 + 无 STUN 泄漏 + 账号注册资料一致。

## 施工流程

### Phase 0：只读审计（先于一切修改）
建立信号台账：读 `references/signal-taxonomy.md` 逐面采集现状，产出"信号→当前值→目标值→处置方式"表。只读，不改任何配置。

### Phase 1：出口与分流（references/network-gateway.md）
1. 选定住宅 IP 出口（选购标准见 references/proxy-dns-architecture.md §2），确认 ASN/欺诈分/本地网不劫持 UDP53。
2. 部署网关（推荐自建裸网关形态）+ TUN + 链式；规则五相位定稿（REJECT→进程DIRECT→进程MATCH→域名MATCH→域名DIRECT→私网→GEOSITE/GEOIP,CN→境外UDP拒绝→MATCH兜底）。
3. 直连白名单最小化：每条标注归属与用途，定期按"日志零命中"清理。
4. 验收：出口 IP 全应用一致。

### Phase 1.5：AI 客户端 killswitch（references/killswitch.md）
代理验收通过后，给关键 AI 客户端 exe 装防火墙出站规则（仅放行回环+fake-ip段，其余拒绝）。先回退脚本后安装。商店应用版本漂移由巡检哨兵每日检测。

### Phase 1.6：浏览器分边（references/browser-telemetry.md §0 + killswitch.md）
一台浏览器全覆盖为代理浏览器（killswitch 放行集加内网三段），一台国内直连专用（进程规则 DIRECT，永不访问境外）。新装浏览器必须二选一分边。

### Phase 2：DNS 面（references/proxy-dns-architecture.md §1）
落地 DNS 三层：fake-ip + 关 AAAA + `dns-hijack: any:53` + 境外 DoH-over-proxy（IP 字面量）+ geosite:cn 国内直连。验收：ipleak dnsdetection 解析器全部落在白名单段（每日巡检哨兵固化）。

### Phase 3：系统信号（references/system-signals.md）
时区/区域/locale 统一到掩护身份；轮换 MachineGuid（scripts/rotate-machine-guid.ps1）；服务与自启盘点（DiagTrack/dmwappush 禁用）；输入法/VPN 远控客户端/管家类软件按既定原则处置。

### Phase 4：浏览器（references/browser-telemetry.md §1）
DNS 交系统；WebRtcIPHandling=disable_non_proxied_udp；intl.locale_requested 与界面语言解耦；多身份多 profile；策略残留清理。

### Phase 5：软件面与遥测（references/browser-telemetry.md §2-§4 + system-signals.md）
客户端遥测开关全关；纯遥测域名按温和清单 REJECT（两周观察期，异常即改引流）；helper 探测面靠网络层收口+DoH 硬化；国产自保护软件"允许采集、采集面缺失"。

### Phase 6：账号与元数据残留（references/account-metadata.md）
git 历史改写（epoch 保留时区重标：提交者邮箱全改 noreply、含旧标识才改作者邮箱、时区统一为出口时区；改写前 mirror 备份、force-push 后搜索二次验证）；GitHub noreply 三层对齐；邮箱第三方暴露八源审计；登录时机纪律（账号邮箱/手机/支付国别与画像一致再登录）。

### Phase 7：巡检与运维（references/ops-runbook.md）
部署 scripts/daily-signal-scan.py 为每日定时任务（cron 避开整点/半点）；信号台账随改动更新；回退纪律与事故恢复顺序常备；升级四键核验；双开处置。

### 贯穿：缺口管理（references/capability-gaps.md）
每个 Phase 完工后对照缺口清单：新出现的"做不到"加一行；已知残余被巡检误报时先查清单再动手。

## 参数与脱敏

本 skill 不含任何真实个人数据。机器相关取值一律由使用者环境决定：

| 占位 | 环境变量/位置 | 示例（虚构/保留段） |
|---|---|---|
| 住宅出口基线 IP | `SIGNAL_BASELINE_IP` | `203.0.113.10` |
| 国内 DNS 引导 IP | `DOMESTIC_DNS_IP`（默认 223.5.5.5） | 按当地网络调整 |
| 客户端生成配置路径 | `CLIENT_CONFIG_YAML` | 各客户端不同 |
| 日常直连白名单 | 台账维护 | 工作网域名、常用国内服务 |

## 文件导航

- `references/signal-taxonomy.md` — 全信号面总表（8 大类 + 治理运维面；每面：信号/途径/目标状态/验证），Phase 0/3/5/6 工作底稿
- `references/network-gateway.md` — 捕获双通道、五相位规则、进程探测对抗、链式出口、自建与 GUI 两种部署形态
- `references/proxy-dns-architecture.md` — DNS 三层设计（DoH-over-proxy）、住宅 IP 选购、GUI 客户端存储模型
- `references/killswitch.md` — 防火墙 fail-closed 兜底（桌面端 + 浏览器变体）
- `references/browser-telemetry.md` — 浏览器角色分边、指纹一致化、遥测温和清单、helper 探测面
- `references/system-signals.md` — 系统/硬件指纹收敛、服务盘点、VPN 客户端处置、权限纪律
- `references/account-metadata.md` — git 历史改写 playbook、GitHub 账号设置、邮箱第三方暴露审计、登录时机纪律
- `references/ops-runbook.md` — 每日巡检哨兵、信号台账、回退纪律、事故恢复、升级四键、双开处置
- `references/lessons.md` — 事故录与决策记录（每个重大决策的当时情境与推理链）
- `references/capability-gaps.md` — 能力边界与诚实缺口清单（结构性/采集面/判定残余/体系外）
- `scripts/daily-signal-scan.py` — 每日哨兵巡检（纯标准库，基线经环境变量注入）
- `scripts/rotate-machine-guid.ps1` — MachineGuid 备份+轮换（需提权一次）
- `scripts/killswitch-install.ps1` / `killswitch-rollback.ps1` — 防火墙 killswitch 安装/回退
- `scripts/dns-forwarder.py` — 已退役方案存档（不接受 DoH nameserver 的旧客户端形态参考）
