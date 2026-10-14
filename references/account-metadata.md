# 账号与元数据暴露面 playbook（git / 邮箱 / 第三方画像关联）

本文件是 Phase 6 的执行细则。核心威胁模型：邮箱是跨服务实体键，git 元数据是挂在实体键上的公开作息/位置标签，数据合作方（政策明确存在交换）可据此做跨源一致性比对。目标状态=实体键公开面上无任何真实身份与真实时区。

## §1 Git 历史改写（epoch 保留时区重标法）

适用：所有**保留**的仓库（无论公开/私有；私有不等于永远私有：协作者、转公开、被 fork 都会暴露）。不再保留"保真提交"的口径——历史全部改写，只保留代码内容。

改写规则（三条同时执行）：

1. 作者/提交者邮箱 → GitHub noreply（`<id>+<login>@users.noreply.github.com`），名字保持中性。
2. 时区偏移重标：每个提交的 **epoch 绝对时刻不变**，仅把偏移从真实值（如 `+0800`）改为掩护国（如 `+0900`）。作息图案被洗成掩护国，仓库时间线完全不变。
3. 全分支 + 全标签改写；merge commit 双 parent 结构由 `git filter-branch --env-filter` 天然保留；禁用 `--prune-empty`。

执行纪律：

- **先备份**：`git clone --mirror` 到独立目录（含 refs/original 可完整回滚），备份 commit 数与远端核对一致后才 force-push。
- **force-push 后验证**：① 远端直接取提交对象核对新邮箱/新偏移/epoch 一致；② GitHub commit 搜索（`search/commits?q=author-email:<旧邮箱>`）两个旧邮箱变体 total 应归零（索引有延迟，以仓库 `git log` 全分支无残留为准）。
- **残留面（诚实清单）**：PR 引用（`refs/pull/*`）GitHub 拒绝推送改写，公开仓的 PR 页面仍指向旧提交，只能网页逐个删除；公开仓旧提交可能已被第三方镜像缓存，缓解=新服务不再用旧邮箱。
- **本地断源**：改写后立刻把 `~/.gitconfig` 全局 `user.email` 换成 noreply——否则下一个新仓库又把真实邮箱写回去（真实发生过）。
- 新仓库默认身份 = 中性名 + noreply；只有明确需要真实身份的场合（如雇主仓库）才逐仓库覆盖。

## §2 GitHub 账号设置

- 主邮箱 visibility → **private**（注意现行端点是 `PATCH /user/email/visibility`，无 id）。
- Profile README 不得含真实邮箱（mailto 链接、联系方式块），仓库描述/website 字段同理。
- 资料页 location/company/twitter 留空或掩护值；bio 不含地域线索。

## §3 邮箱第三方暴露面审计（年度/注册新服务前必做）

对真实邮箱的每个变体（大小写/点号/旧邮箱）执行：

| 源 | 方法 | 处置 |
|---|---|---|
| 泄露库 | XposedOrNot API（免费免key）；HIBP 网页版人工复核（源更多） | 命中→改密码+该邮箱不再注册新服务 |
| 搜索引擎索引 | 精确串搜 `"<email>"`（含 paste/论坛/人肉站） | 命中→联系删除或弃用该邮箱 |
| Gravatar | MD5(邮箱) 探 `gravatar.com/<hash>.json` 与 avatar 404 | 有资料→删除或换邮箱 |
| GitHub code search | `gh api search/code?q=<email>` | 命中→按 §1 改写 |
| GitHub commit search | `gh api search/commits?q=author-email:<email>` | 命中→按 §1 改写 |
| 其他代码托管 | GitLab 登录后搜索（未登录 API 返回 401） | 命中→改写/删除 |
| Google 账号 | 安全页第三方应用授权清单 | 撤掉不认识的 |
| Gmail | 自搜 `welcome OR verify OR 注册` | 盘点注册过的服务，弃用的注销 |

## §4 登录时机纪律

AI 桌面端/网页端的配置目录审计（`%APPDATA%\<App>\config.json`）：登录态哨兵（Electron 常见键如 `windowSizeWasSignedIn`、有无 userId）、分析设备 ID（ant-did 类，服务商固有接受项）、遥测计划任务。**账号绑定前的窗口是调整画像的唯一时机**——所有信号面验收 PASS 后再登录；登录后该面由服务端画像接管。

## §5 复核节奏

- 每日巡检：gitconfig 身份哨兵（不含真实邮箱）。
- 月度：GitHub commit 搜索旧邮箱变体 total=0。
- 年度/新注册服务前：§3 全套。
