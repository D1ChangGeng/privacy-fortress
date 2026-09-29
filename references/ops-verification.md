# 运维与验证

## 目录
- [§1 每日巡检清单（18 项）](#1-每日巡检清单18-项)
- [§2 检测站与通过标准](#2-检测站与通过标准)
- [§3 运维纪律](#3-运维纪律)
- [§4 基线管理](#4-基线管理)

## §1 每日巡检清单（18 项）

`scripts/daily-signal-scan.py` 实现，纯 Python 标准库，不消耗对话额度。基线经环境变量注入（见 §4）。

| # | 探测项 | 判据 |
|---|---|---|
| 1 | TUN 设备状态 | 虚拟网卡在 = PASS |
| 2 | 出口 IP 一致性 | = SIGNAL_BASELINE_IP；出现任何中国段公网 IP = FAIL |
| 3 | Cloudflare trace | 出口 IP 与 trace IP 一致 = PASS（cf 校验通道正常） |
| 4 | 出口归属/ASN | ipinfo 国家 = 掩护国，org 非数据中心特征 |
| 5 | WebRTC STUN | 无真实公网 IP 泄漏 |
| 6 | IPv6 出口 | 无 v6 公网出口 |
| 7 | DNS 解析一致性 | 系统解析结果与隧道解析一致 |
| 8-17 | 配置完整性哨兵（设 CLIENT_CONFIG_YAML 时启用） | nameserver=127.0.0.1 / dns-hijack / MATCH 兜底 / DoH 硬化四键在生成配置中在位，被客户端漂移覆写即 FAIL |
| 18 | 白名单快照（设 REQUIRED_DIRECT 时启用） | 必需直连条目在位 + 已清除条目回潮即 FAIL |
| 19 | DNS 转发器健康 | 127.0.0.1:53 应答正常 = PASS；无应答/SERVFAIL = FAIL（核心已回落，查询面暴露） |
| 20 | 检测站可达性 | 9 站 HTTP 200 |

报告输出：Markdown 当日报告 + PASS/WARN/FAIL 结构化判定 + 人工复核清单（需浏览器 JS 的深度项）。

部署为每日定时任务：cron 避开整点/半点（建议 `52 5 * * *` 类错峰分钟），时区按使用者本地。FAIL 项当天处理；WARN 项记入台账观察。

## §2 检测站与通过标准

| 站点 | 看什么 | 通过标准 |
|---|---|---|
| `ip.net.coffee/claude/` | 目标 AI 服务视角的整体风险面 | 过关项全绿；语言/时区/IP 信号不命中真实所在地 |
| `ip.net.coffee/dns/`（深度测试） | DNS 泄漏 | 中国 DNS 条目清零。**测前必须确认 TUN 已开启**，否则本地网络直连会误报 |
| `ip.net.coffee/webrtc/` | WebRTC 泄漏 | 只显示出口 IP，无本地/真实公网 IP |
| `ip.net.coffee/cloudflare/` | CF 校验 | 能过 CF 校验页（住宅 IP 基本要求） |
| `iplark.com` | C 段画像/AI 检测/代理检测/IPv6 | AI 检测与代理检测"检测失败"；IPv6 出口"获取失败" |
| `ippure.com` | 人机占比 | 人类流量占比高 |
| `ippure.com/claude.html` | Claude 专项面 | 风险分低于站点阈值；语言/字体信号不命中 |
| `ippure.com/DNS-Leak-Detect.html` | DNS 泄漏专项 | 每次必测：中国条目清零 |
| `scamalytics.com` | 欺诈分 | Fraud Score 低 |
| `cc.mastersgo.cc` | 过关清单 | 未过关项逐条处置 |

**每周人工复核**（脚本替代不了）：DNS 深度测试、claude 过关项逐条、iplark 三指标、过关清单未过项。结果记台账。

## §3 运维纪律

1. 改库先备份（时间戳后缀）→ 重启客户端 → 核验生成配置 → 端到端实测。四步缺一不算完成。
2. 以生成配置为准，不以 UI 或数据库行数为准（客户端渲染存在启用/停用双行与跨 profile 行）。
3. 规则只增不滥：新增直连白名单必须标注归属与用途；定期按"日志零命中+归属核验"清理（IP 规则用 ipinfo 类服务核归属，境外 IP 直连=对方可见真实出口，优先清除）。
4. 失联恢复顺序见 proxy-dns-architecture.md §6。
5. 历史中间文件按白名单清理：只留文档台账、在役脚本、每系列最新一份配置备份；清理明细留日志文件。
6. 巡检报告与信号台账是持续运维载体——新增/关闭任何信号面的处置都记台账变更记录（版本号+日期+证据）。
7. 卸载任何软件后，立即审计其计划任务/启动项/驱动残留（卸载程序普遍不自净）。排查法：`Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; StartTime=<近2小时>}`，触发间隔异常（如每 2 分钟）的自家任务是重点怀疑对象。
8. 注册表写入必须二次读取校验（写入与读回值一致才算完成）。曾发生"轮换 MachineGuid 以为成功、数日后核查仍为旧值"的案例——不校验的写入等于没做。
9. 系统重装/恢复后，HKCU 下的隐私策略（如 Chrome WebRtcIPHandling、locale）全部归零，须在巡检中重验并补写；把"重装后首巡"当作一次全新部署对待。
10. 新装目标应用后审计其配置目录（如 Electron 应用的 `%APPDATA%\<App>\config.json`）：登录态（无 userId / windowSizeWasSignedIn=false 即未绑定账号）、分析设备 ID（ant-did 类）、遥测计划任务（如 Cowork VM 组件首次使用才落地，落地即复扫）。账号绑定前的窗口是调整画像的唯一时机。
11. 共享运行时白名单必须用 PROCESS-PATH（完整路径）而非 PROCESS-NAME：node.exe/python.exe 是所有 Node/Python 程序的共用进程名，按名字放行=把同机所有 CLI 工具（包括 AI CLI）放出隧道。Kimi Work 的 runtime node 用精确路径白名单，全局 node 落兜底 MATCH 即为正确隔离（2026-09-30 核查确认）。
12. 区域格式（Culture/LocaleName，决定货币符号/日期格式）是 IP↔locale↔currency 一致性轴的一部分，必须与出口国对齐（如 ja-JP）；显示语言可独立保持母语，两者互不影响。

## §4 基线管理

| 环境变量 | 用途 | 未设置时 |
|---|---|---|
| `SIGNAL_BASELINE_IP` | 住宅出口基线（必填） | 巡检该项报 WARN 并提示配置 |
| `DOMESTIC_DNS_IP` | 国内引导 DNS | 默认 223.5.5.5 |
| `CLIENT_CONFIG_YAML` | 客户端生成配置路径 | 配置哨兵跳过 |
| `REQUIRED_DIRECT` | 逗号分隔的必需直连条目 | 快照哨兵跳过 |
| `FORBIDDEN_DIRECT` | 逗号分隔的已清除条目（回潮检测） | 快照哨兵跳过 |
| `FORWARDER_PORT` | 转发器端口 | 默认 53 |

基线变更（换节点/IP）流程：新基线实测达标（§2 全套）→ 更新环境变量 → 当日巡检确认 PASS。
