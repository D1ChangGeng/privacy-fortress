---
name: privacy-fortress
description: 将一台大量泄露真实位置/身份信号的 Windows 电脑改造为最小信息暴露面。覆盖全部信号面：网络出口一致性、DNS 查询面、WebRTC/IPv6 泄漏、系统与硬件指纹（时区/语言/MachineGuid/设备名）、软件面与遥测、浏览器指纹、账号与 git 元数据、本地网络邻近、主动探测面。包含分阶段施工流程（每阶段先写回退脚本+超时防线）、Clash 系客户端分流规则与 DNS 转发器架构、每日自动巡检脚本与检测站清单。适用：用户要求"防止应用/web/AI 服务通过多信号综合分析推断我的真实地理位置或身份"、隐私加固、代理+TUN 环境搭建、DNS 防泄漏、每日隐私巡检。不适用于：已构成犯罪的规避执法需求、iOS/Android 设备（本 skill 针对 Windows）。
---

# Privacy Fortress：最小信息暴露面改造

把"每个应用各自裸连、信号散落各处"的电脑，改造为"所有出境流量统一走受控出口、所有信号面要么收敛为掩护身份、要么闭合"的状态。读者（人或 Agent）不需要看过任何历史会话，按本文件即可执行。

## 五条施工纪律（每条都对应一类已发生过的系统级事故）

1. **回退先行**：每个阶段动手前，先写该阶段的回退脚本并实测可运行；预估可能断网的步骤，必须设立"超时未确认则自动回退"防线。系统级事故优先级高于一切隐私目标。
2. **温和不破坏联网**：引流（match 到代理）优先于拦截（REJECT）。拦截只用于纯遥测域名。绝不让"默认禁止所有出站"这类配置落地。
3. **端到端验收**：每个阶段改完，以"本机日常关键应用仍能联网工作"为最高优先级验收项（对用户自己正在使用的 AI 客户端/浏览器/通讯工具，逐一手动验证）。
4. **改配置先备份**：修改任何配置文件/数据库前，先留时间戳备份；生效路径=备份→修改→重启客户端→核验生成物→实测。
5. **诚实残留**：做不到的面（如服务商侧 KYC、WiFi 邻近 SSID）明确记入台账，标注为"接受残留"，假装闭合比承认残留更危险。

## 总体架构（最终状态）

```
应用流量
  ├─ 白名单进程（日常国内应用）──→ 直连（最小化、逐条有身份）
  ├─ REJECT 名单（纯遥测域名）──→ 拒绝
  └─ 其余全部流量 ──→ TUN 接管 ──→ 兜底 MATCH ──→ 链式代理 ──→ 住宅 IP 出口
                                                       ↑
系统 DNS ──→ 127.0.0.1:53 本地转发器 ──→ DoH(1.1.1.1) ───────┘（境外查询全程境外发出）
   （转发器故障时核心回落国内 DNS，保联网，查询面降级记 WARN）
```

掩护身份基线（由用户确认后全机统一）：同一住宅 IP 出口 + 目标国家时区 + 目标国家系统区域/语言 + 浏览器语言指纹一致 + 无 IPv6 出境 + 无 STUN 泄漏。

## 施工流程

### Phase 0：只读审计（先于一切修改）
建立信号台账：枚举当前每个信号面的真实取值与泄露途径。读 `references/signal-taxonomy.md` 的"信号面总表"，逐面采集现状并记录。产出：一张"信号 → 当前值 → 目标值 → 处置方式"的台账。此阶段只读，不改任何配置。

### Phase 1：出口与分流（先看 references/proxy-dns-architecture.md §1）
1. 选定住宅 IP 出口（选购标准见 §3），确认其 ASN/城市/欺诈分达标。
2. 搭建代理客户端 + TUN + 链式（如需要），规则顺序定稿：**进程白名单 → 链式域名组 → 国内域名白名单 → IP 白名单 → DoH 硬化 → 兜底 MATCH**。所有 match 类规则位于兜底之前；REJECT 仅纯遥测域名且置于白名单之后。
3. 直连白名单最小化：每条规则标注归属与用途，定期按"日志零命中"清理。
4. 验收：出口 IP 全应用一致（用 `scripts/daily-signal-scan.py` 的 exit_ip 探测）。

### Phase 2：DNS 面（references/proxy-dns-architecture.md §2-§4）
按五层设计落地：fake-ip + 关 AAAA + `dns-hijack: any:53` + nameserver 首查本地转发器 + 国内域名国内解析。部署 `scripts/dns-forwarder.py` 并设开机自启。验收：DNS 泄漏检测站中国条目清零（见 references/ops-verification.md）。

### Phase 3：系统信号（references/signal-taxonomy.md §系统层）
时区/区域/语言/locale 统一到掩护身份；轮换 MachineGuid（`scripts/rotate-machine-guid.ps1`）；评估设备名/用户名/MAC/SMBIOS（改动有代价，按威胁模型决定，台账记录）。

### Phase 4：浏览器（references/browser-telemetry.md §1）
DNS 交给系统（DoH 关闭或用系统默认）；WebRTC IPHandling 设为禁用非代理 UDP；`intl.locale_requested` 与界面显示语言解耦（显示中文、指纹报目标语言）；多身份用多 profile 隔离。

### Phase 5：软件面与遥测（references/browser-telemetry.md §2-§3）
客户端遥测 env 开关全部关闭；遥测域名按温和清单 REJECT；helper 进程偷跑国内 DoH/偷 ping 的通道封死（DoH 端点整体压进隧道）；国产自保护软件按"允许采集、采集面缺失"原则处置，不卸载。

### Phase 6：账号与元数据残留（references/signal-taxonomy.md §账号层）
git 提交时区/邮箱元数据清理（历史仓库按留三条保真、其余删除的口径执行）；客户端设置文件清历史语言痕迹；历史中间文件与备份序列按白名单清理。

### Phase 7：巡检自动化（references/ops-verification.md）
部署 `scripts/daily-signal-scan.py` 为每日定时任务（cron 避开整点/半点，建议 7-23 或 37-53 分），基线 IP 用环境变量 `SIGNAL_BASELINE_IP` 注入。每日报告 PASS/WARN/FAIL；FAIL 项当天处理。检测站浏览器深度项列入人工复核清单，每周手动过一遍。

## 参数与脱敏

本 skill 不含任何真实个人数据。机器相关取值一律由使用者环境决定，通过环境变量或台账填入：

| 占位 | 环境变量/位置 | 示例（虚构） |
|---|---|---|
| 住宅出口基线 IP | `SIGNAL_BASELINE_IP` | `203.0.113.10`（文档保留段，实际填真实基线） |
| 国内 DNS 引导 IP | `DOMESTIC_DNS_IP`（默认 223.5.5.5） | 按当地网络调整 |
| 代理客户端配置路径 | `CLIENT_CONFIG_YAML` | 各客户端不同 |
| 日常直连白名单 | 台账维护 | 校园网/工作网域名、常用国内服务 |

## 文件导航

- `references/signal-taxonomy.md` — 全信号面总表（每面：信号/途径/目标状态/验证），Phase 0/3/5/6 的工作底稿
- `references/proxy-dns-architecture.md` — 分流规则设计、DNS 五层架构、转发器部署、链式注意点、事故恢复顺序
- `references/browser-telemetry.md` — 浏览器指纹一致化、遥测阻断温和清单、helper 探测面防护
- `references/ops-verification.md` — 18 项巡检清单、9 个检测站及通过标准、运维纪律
- `scripts/dns-forwarder.py` — 本地 DNS 转发器（127.0.0.1:53 → DoH，上游故障回 SERVFAIL 触发核心回落）
- `scripts/daily-signal-scan.py` — 每日信号面巡检（纯标准库，基线经环境变量注入）
- `scripts/rotate-machine-guid.ps1` — MachineGuid 备份+轮换（需提权，UAC 一次）
