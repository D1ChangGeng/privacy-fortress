# privacy-fortress

Windows 最小信息暴露面改造 Skill：把一台大量泄露真实位置/身份信号的电脑，改造为所有出境流量统一走受控住宅出口、所有信号面收敛为掩护身份的状态。

## 防什么

应用与网站的自动化系统（含 LLM 综合分析）正通过**多信号拼接**推断你的真实地理位置与身份：出口 IP、DNS 查询记录、WebRTC、时区/语言/MachineGuid、已安装软件、输入法词库、git 提交里的邮箱与时区、VPN 客户端记录的真实端点、浏览器语言指纹……单个信号都不致命，拼起来就是答案。

本 skill 把每个信号面逐一处置：**收敛**（改成掩护身份的取值）、**闭合**（堵住通道）、或**诚实记录为接受残留**——并在防护之上建立每日自动巡检，让任何一层静默失效都会在第二天报告里现身。

## 能力全景

| 层 | 覆盖 |
|---|---|
| 捕获 | TUN 内核级全接管 + 系统代理双通道；管理员权限不可绕过 |
| DNS | 53 劫持 + fake-ip + 境外 DoH-over-proxy（根治本地网关劫持 UDP53 上送运营商）+ 国内分流 |
| 分流 | 五相位规则：遥测掐死→白名单直连→可疑进程送链→目标域送链→国内直连→MATCH 兜底（绝不允许直连兜底） |
| 出口 | 中转 VPS + 住宅 IP 两跳链式；境外 UDP 闭合 |
| 兜底 | 防火墙 killswitch（fail-closed）：误关代理时关键应用宁断不漏 |
| 浏览器 | 代理/国内双浏览器分边；WebRTC 收口；语言指纹与界面解耦；多身份多 profile |
| 系统 | 时区/区域/MachineGuid/服务盘点/输入法/VPN 客户端/管家类软件既定处置 |
| 账号 | git 历史改写、GitHub 三层对齐、邮箱第三方暴露八源审计、登录时机纪律 |
| 运维 | 每日哨兵巡检、信号台账、回退脚本先行、升级四键核验、双开处置 |
| 边界 | 能力缺口清单：代理服务商侧知情、账号强绑定、rootkit 等明确承认并给缓解 |

## 安装

**方式一：npx（推荐，一条命令）**

```bash
npx skills add D1ChangGeng/privacy-fortress
```

**方式二：git clone**

把本仓库放入你的 skills 目录（`~/.config/agents/skills/` 或项目级 `.agents/skills/`）。

**方式三：`.skill` 包**

从 [Releases](https://github.com/D1ChangGeng/privacy-fortress/releases) 下载 `privacy-fortress.skill`，解压到 skills 目录。

## 使用

对 Agent 说：

> 按 privacy-fortress 把我的电脑改造成最小信息暴露面。

或只施工某一个阶段（如"按 privacy-fortress Phase 2 落地 DNS 面"）。Agent 应从 Phase 0 只读审计开始，逐阶段执行；每阶段遵守五条施工纪律（回退先行/温和不破坏联网/端到端验收/改配置先备份/诚实残留）。

## 结构

- `SKILL.md` — 施工纪律 + 8 阶段流程 + 文件导航
- `references/` — 信号面总表、网关与 DNS 架构、killswitch、浏览器与遥测、系统信号、账号元数据、运维体系、事故录、缺口清单
- `scripts/` — 每日哨兵巡检、MachineGuid 轮换、killswitch 安装/回退（基线全部经环境变量注入，零硬编码）

机器相关取值（住宅出口基线 IP、客户端配置路径、直连白名单）由使用者环境决定，通过 `SIGNAL_BASELINE_IP` 等环境变量注入，详见 `references/ops-runbook.md`。

## 作者实测在用的服务

本 skill 的网络层设计全部在以下服务上长期验证（可作选购基准参照）：

- 住宅 IP：[IPDEEP](https://www.ipdeep.cn/?extendid=821fNWE0ODI3MzA2OTM4MzAxMTUzMzUx)——真家宽段，本 skill 巡检基线 IP 即出自该服务
- 机场/链式代理（GUI 客户端形态基准）：[蜂窝加速器](https://share.fengwo.live#/register?code=yxRGajMF)——支持链式代理与 TUN 全局接管

选购判据与检测方法见 `references/proxy-dns-architecture.md` §2。

## 诚实声明

本体系**不声称**做到：代理服务商侧不可知你的真实来源、账号强绑定资料（手机/支付）可匿名、恶意驱动可配置层防御、以及"在国内"这一低精度信号可隐藏。完整清单与缓解手段见 `references/capability-gaps.md`。隐私防护的目标是把信号面收敛到"对方自动化系统无法综合分析出你的真实地理位置与身份"，而不是隐身。

## 适用边界

Windows 桌面环境；Clash/Mihomo 兼容内核。不含任何预设的个人数据或机器标识。不适用于规避执法等已构成犯罪的需求。
