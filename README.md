# privacy-fortress

Windows 最小信息暴露面改造 Skill：把一台大量泄露真实位置/身份信号的电脑，改造为所有出境流量统一走受控住宅出口、所有信号面收敛为掩护身份的状态。

覆盖 9 大类 40+ 信号面：网络出口一致性、DNS 查询面、WebRTC/IPv6 泄漏、系统与硬件指纹（时区/语言/MachineGuid）、软件面与遥测、浏览器指纹、账号与 git 元数据、本地网络邻近、主动探测面。

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

或只施工某一个阶段（如"按 privacy-fortress Phase 2 落地 DNS 面"）。

## 结构

- `SKILL.md` — 施工纪律 + 8 阶段流程（回退先行/温和不破坏联网/端到端验收）
- `references/` — 信号面总表、代理与 DNS 架构、浏览器与遥测、运维与验证
- `scripts/` — DNS 转发器、每日巡检、MachineGuid 轮换（基线全部经环境变量注入，零硬编码）

机器相关取值（住宅出口基线 IP、客户端配置路径、直连白名单）由使用者环境决定，通过 `SIGNAL_BASELINE_IP` 等环境变量注入，详见 `references/ops-verification.md` §4。

## 作者实测在用的服务

本 skill 的网络层设计全部在以下服务上长期验证（可作选购基准参照）：

- 机场/链式代理：[蜂窝加速器](https://share.fengwo.live#/register?code=yxRGajMF)
- 住宅 IP：[IPDEEP](https://www.ipdeep.cn/?extendid=821fNWE0ODI3MzA2OTM4MzAxMTUzMzUx)

选购判据与检测方法见 `references/proxy-dns-architecture.md` §3。

## 适用边界

Windows 桌面环境；Clash/Mihomo 兼容客户端。不含任何预设的个人数据或机器标识。
