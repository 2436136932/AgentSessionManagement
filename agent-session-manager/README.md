# Agent 会话管理器 (Agent Session Manager)

一个**本地、Windows 优先**的可视化工具，用来统一管理电脑上各个 AI Agent 的会话数据：
自动识别装了哪些 Agent、把它们散落在多处的会话列在一起、并能**安全删除**（连索引残留一起清理）。

> 全程本地运行，**不联网、不上传任何数据**。删除默认进入隔离区，可一键还原。

---

## 为什么需要它

一个会话往往**不是**一个文件，而是散落在多个位置。手工删文件夹必然留下残渣：

**DeepSeek Harness 的一个会话横跨 4 个地方**

| 位置 | 内容 | 不一起删的后果 |
|---|---|---|
| `~/.dsh/sessions/<工作区>/<会话id>/session.v4.jsonl.zstd` | 对话正文（zstd 压缩） | — |
| `~/.dsh/storages/session_projcache/sessions/<会话id>.json` | 标题、首条提问 | 侧边栏留下**点不开的幽灵条目** |
| `~/.dsh/storages/workspace.json` | 工作区 → `sessionIds` | 会话"复活"或列表错乱 |
| `~/.dsh/attachments/v1/objects/<aa>/<sha256>` | 内容寻址附件，**多会话共享** | 盲删会**破坏其他会话的附件** |

其他 Agent 也有各自的坑：

- **WorkBuddy**：SQLite + `deleted_at` **软删除**——标成删除**不释放空间**，行还在。
- **Copilot Chat**：有 **FTS5 全文索引**，只删会话表 → 已删内容**仍能被搜到**。
- **CodeBuddy / Antigravity**：会话元数据分散在多个文件与小数据库中。

本工具把这些当作**一个整体**处理：解析 → 出计划 → 备份 → 执行 → 校验 → 可还原。

---

## 快速开始

```bat
双击 start.bat
```

或手动：

```powershell
python server.py            # 默认 http://127.0.0.1:8799/
python server.py --port 9000 --no-browser
```

浏览器会自动打开。按 `Ctrl+C` 停止。

**命令行**：所有功能也可脚本化，见 [cli.py](cli.py)。

```powershell
python cli.py scan                       # 扫描所有 Agent 的会话与占用
python cli.py sessions --agent dsh       # 列出会话
python cli.py plan --agent dsh --sid <id>    # 审阅删除计划（只读）
python cli.py delete --agent dsh --sid <id> --yes
python cli.py residue --agent workbuddy  # 残留报告（只读）
python cli.py cleanup --agent workbuddy --dry-run
python cli.py cleanup --agent workbuddy --dispositions safe
python cli.py uninstall --agent workbuddy --preflight-only
python cli.py quarantine                 # 隔离区与保留策略
python cli.py history --record           # 记录占用快照
python cli.py dupes                      # 重复内容检测（只读）
python cli.py secrets                    # 敏感信息扫描（只读）
python cli.py projects                   # 按项目聚合
python cli.py report                     # 各 Agent 卸载/回收概览
```

退出码：`0` 成功，`1` 错误，`2` 被安全检查拒绝。所有破坏性命令都需要 `--yes`，且都支持 `--dry-run`。

**要求**：Python 3.12+（用到标准库 `compression.zstd`，3.14 已内置）。**无需安装任何第三方包。**

---

## 界面功能

| 页面 | 内容 |
|---|---|
| **总览** | 每个 Agent 一张卡：是否安装、会话数、占用空间、文件数、是否运行中；下方列出「检测到但尚未支持」的程序与可回收空间建议 |
| **会话** | 全部会话一张表，可按 Agent / 体积 / 时间 / 标题 / **价值**筛选排序；支持搜索与「只看残留」；**点标题或「查看」预览内容**；每行可**保留 / 导出 / 删除**；可勾选批量删除，**批量删除会先出预演**（列出每项将释放多少、哪些会被安全检查阻止及原因），确认前不改动任何数据 |
| **内容搜索** | **在会话正文中全文检索**（不只是标题），支持按 Agent 过滤、正则、大小写敏感，命中处高亮上下文 |
| **用量** | 按会话统计 **token 用量与费用**：输入 / 输出 / 缓存读取 / 合计，以及 Agent 自己记录的费用 |
| **清理建议** | **保留规则筛选**（幽灵 / 孤儿 / 空会话 / 长期未用 / 零碎小会话 / 体积过大 / 从未打开）+ 结构性问题（无引用附件、空目录、软删除残留、空数据库） |
| **卸载清理** | **彻底退场**：按 Agent 预检 → 调用官方卸载器 → 卸载后验证 → **残留分级清理**（可安全 / 需确认 / 禁止）→ 报告与还原；含隔离区保留策略 |
| **操作记录** | 每次删除与清理的完整记录，可**一键还原** |

### 卸载清理页做了什么

这是「不想用某个 Agent 了，想删干净」的入口。实测它在本机发现了 **350.4 MB 可安全回收**的残留（缓存、日志、空壳目录），以及不删就会一直留着的密钥文件、注册表键、防火墙规则和快捷方式。

**分级处置**是这一页的核心。每一项残留都归入三档之一，并附**判定依据**：

| 档位 | 含义 | 默认 |
|---|---|---|
| 可安全清理 | 明确属于该 Agent 且可再生（纯缓存、日志、空目录） | 已勾选 |
| 需人工确认 | 属于该 Agent 但可能有用（会话、配置、插件、二进制、凭据） | 未勾选 |
| 禁止删除 | 用户数据、共享资源、源码仓库 | 只读展示原因 |

之所以要有第三档，是因为本机真实存在 `E:\workbuddyapi-main`——一个用户自己的 git 仓库，里面恰好有个 `.codebuddy` 目录。任何"按关键词扫盘"的清理工具都会把它删掉。归属模型（`core/ownership.py`）按**证据**而不是名字判定：`.git` / `package.json` 等特征文件命中即判 `禁止`，并且在**执行前重新分类**（纵深防御，`selftest_residue.py` 专门断言这一点）。

**5 阶段向导**：预检（进程 / 保留标记 / 凭据）→ 调用官方卸载器（注册表里的 `QuietUninstallString`，唯一不可逆的一步，必须勾选确认框 + `confirm()`）→ 卸载后验证（重新扫描，不信卸载器的"成功"返回值）→ 残留分级清理（支持**预演**，未确认前不碰任何文件）→ 报告与还原。

**其它保障**：`HKLM` 键与防火墙规则需要管理员，本工具**不会尝试提权**，而是给出可复制的命令；删注册表键前先 `reg export` 备份到隔离区，可还原；Agent 运行中只允许预演，真正执行会被拒绝。快捷方式是普通 `.lnk` 文件，走同一条可还原的文件路径（移入隔离区），但**只有需管理员的那些**才降级为给出命令。

**会计恒等式**：清理结果自带 `accounting` 字段，保证 `选中 = 已执行 + 已报告`。任何既没被执行、也没出现在 `reported` 里的项目都会被测试判为失败——这条不变量是专门为「快捷方式曾被静默丢弃」这个真实缺陷加的：它被选中后既不删除也不报告，界面却显示清理成功。现在无法自动处理的项一律进入 `reported`，附原因和可直接复制的命令。

### 归属与缓存

总览里的「占用空间」是 Agent 整棵目录树。实测 **DSH 745 MB 里真正的会话只有 7.7 MB（约 1%）**，其余是浏览器内核、组件缓存和插件。「卸载清理」页把这两者分开：可再生缓存（`GPUCache`、`component_crx_cache` 等）判为可安全清理；**有状态存储**（`Local Storage`、`state.vscdb`、数据库预写日志）判为需确认——删了会丢失登录态或损坏数据库。

### 价值分级（辅助判断该不该删）

会话列表有一列「价值」，按**本机可见的事实**估算 0–100 分，分为四档：
`值得保留` / `可以保留` / `价值较低` / `基本无价值`。

五个信号加权得出，鼠标悬停可看到具体构成：**对话轮次、token 投入、内容体量、工具调用、磁盘占用**。

**关键设计：不确定时明确说「无法评估」。**
如果一个会话评分为 0 只是因为**它的正文不在本机**（例如 WorkBuddy 的对话存在云端），
它会被标为 **「无法评估」** 而不是「基本无价值」——否则会诱导用户把有价值的云端会话当垃圾删掉。
评分只是建议，**不是删除依据**。

### 两层保留保护

误删是这类工具最大的风险，所以做了两级保护，**会话级**与**工作区级**：

| 级别 | 保护范围 | 典型用途 |
|---|---|---|
| **会话级** | 单个会话 | 「这次对话很重要，别删」 |
| **工作区级** | 该文件夹下**所有**会话，**含将来新增的**、含子目录 | 「这个项目别清理」 |

工作区匹配是按**路径前缀 + 边界**判断的，因此：

- `E:\proj` 能覆盖 `E:\proj\sub\deep`（子目录）
- `E:\proj` 能覆盖将来才创建的 `E:\proj\new-session`（因为规则基于路径，不基于会话 ID）
- `E:\proj` **不会**误伤 `E:\proj2`（边界判断，不是简单字符串前缀）
- 大小写与结尾斜杠都做了归一化

被保护的会话在列表里显示**保留**或**工作区保留**标记；删除时**直接拒绝**（HTTP 409），
并说明原因；要删除必须**显式**勾选「忽略保留标记」，且该操作**不会**取消标记本身。
清理建议同样会跳过受保护的会话，并单列「已跳过 N 个保留项」。

### 借鉴了同类项目的哪些做法

调研了 GitHub 上 20+ 个同类项目（详见文末「调研结论」），把其中有价值的设计拿了进来：

| 借鉴的能力 | 来自 | 本工具的实现 |
|---|---|---|
| **删除索引项，而不只是正文** | SessionSweep | 已实现（DSH `workspace.json`、VS Code FTS + `state.vscdb`、CodeBuddy 项目索引） |
| **计划与确认之间做指纹校验** | session-steward | **已实现**：`plan_fingerprint()` 在确认时重算，内容变了就取消删除 |
| **保留保护，含工作区级联** | session-steward | **已实现**：会话级 + **工作区级**（覆盖子目录与将来新增的会话），删除前强制检查 |
| **幽灵 / 孤儿 / 空白 三态标记** | SessionSweep | 已实现（幽灵 / 孤儿 / 空会话规则） |
| **运行中会话检测** | 三者皆有 | 已实现（进程 + 10 分钟写入窗口），并修掉了「`.exe` 后缀不匹配导致防护静默失效」 |
| **保留规则（按龄 / 按体积）** | session-steward | **已实现**：`core/retention.py`，7 条规则，只建议不执行 |
| **Token 用量分桶核算** | orrery / session-steward | **已实现**：`core/usage.py`，输入 / 输出 / 缓存读写 / 合计 |
| **清理评分与价值分档** | cc9s（调研发现的同类项目） | **已实现**：`retention.score_session()`，4 档 + 「无法评估」例外 |
| **导出会话以便留档** | —（三者均无通用导出） | **已实现**：Markdown / 文本 / JSON |
| **本地状态与原子写入** | session-steward | 已实现（临时文件 + `os.replace` + `.bak`） |
| **界面国际化** | orrery | 未做（当前为中文界面），如需可后续加 |

**本工具独有的两点**（调研确认三者都没有）：

1. **正文全文检索**：三个项目的内容搜索都只到「标题 / 路径 / 首条消息 / 会话 ID」，
   没有一个是搜索完整对话正文的。本工具索引 **6 MB 正文**，查询约 **3–26 ms**。
2. **不臆造费用**：只在 Agent 自己记录了金额时才显示（目前是 CodeBuddy 的 credit）；
   DSH 用量账本里记的是 `cost: 0`，不是真实价格，因此不显示为金额，而是明确说明。

另外两处刻意的差异：
- **不自动排程删除**。session-steward 会装 launchd / systemd / schtasks 定时清理；
  本工具只做建议，把执行权留给人。
- **详情如实说明"看不到什么"**：例如 WorkBuddy 的正文在云端、某个 Agent 不记录用量，
  都会明确标注，而不是显示为 0 或空白。

### 会话内容预览（只读）

在「会话」页**点击标题**或点「查看」，即可在弹窗中阅读该会话的实际内容，用来判断到底要不要删：

- 按角色分色显示：**用户 / 助手 / 工具 / 系统**
- 区分内容类型：正文、**思考**（斜体弱化）、**工具调用**（含工具名与参数）、**工具结果**、图片、出错
- 顶部显示工作目录、占用空间、最后活动、消息条数，以及幽灵/孤儿标记
- 不截断的地方如实说明——消息过多、文本过长都会明确标注「已截断」及原长度
- 弹窗底部有「技术细节」折叠区，列出存储位置与字段，便于确认来源
- **严格只读**：只解析、不写入。测试套件会对整个存储目录做**逐字节哈希比对**，证明预览前后完全一致

各 Agent 的预览范围：

| Agent | 预览内容 |
|---|---|
| **DSH** | 完整对话：用户消息、助手回复、思考过程、工具调用与结果、图片 |
| **CodeBuddy** | 完整对话（读取 `messages/<id>.json`，索引与文件一一对应） |
| **Copilot Chat** | 数据库 `turns` 问答对、检查点；jsonl 中的请求与回复 |
| **WorkBuddy** | **无正文可看**（正文在云端）；如实展示本机已有的元数据，并明确说明原因 |
| **Antigravity** | `thinking_records` 思考记录；无记录时展示会话行元数据 |

无法预览时不会只给一个空白框，而是说明**为什么**：幽灵条目（只有索引没有正文）、空会话（正文为空）、云端会话（正文不在本机）、索引残留（既无文件也无消息）——四种情况文案各不相同。

---

## 安全设计

删除走固定的七步流程，任一步失败都会**回滚本次操作**：

```
1. 重新校验  每个路径都必须落在该 Agent 声明的数据目录内；会话 ID 不得含路径分隔符
2. 前置检查  Agent 不得正在运行；计划不得被阻止
3. 备份      会被改动的 SQLite / JSON 索引先做一致性副本
4. 转移      文件与目录移入隔离区（_data/quarantine/<操作号>/）
5. 改库      在有事务保护下删行；JSON 索引用「临时文件 + rename」原子改写
6. 事后校验  重跑该适配器的 verify_absent()
7. 记日志    写入 JSONL，可还原
```

**具体防护**

- **默认进隔离区**，永久删除需要额外勾选二次确认。
- **两层保留保护**：会话级 + 工作区级（含子目录与将来新增的会话），删除前强制检查，可显式覆盖。
- **过期确认保护**：确认删除时会重算指纹，若会话内容在此期间被改动，删除**自动取消**并提示重新确认。
- **运行中保护**：Agent 在跑 **且** 会话在 10 分钟内被写过 → **拒绝删除**（HTTP 409）。
- **路径白名单**：路径越界直接拒绝执行，防止会话 ID 构造出穿越攻击。
- **共享附件保护**：附件是内容寻址的，只有在**没有任何剩余会话引用**时才作为**可选项**提供，默认不删。
- **只读优先**：格式与预期不符时降级为「仅浏览」，绝不猜着删。

> 路径安全校验在 `core/executor.py:validate()`；活动会话判定在 `adapters/dsh.py` 的 `LIVE_WINDOW_MS`。

---

## 支持的 Agent

| Agent | 存储位置 | 浏览 | 删除 | 覆盖的删除目标 |
|---|---|---|---|---|
| **DeepSeek Harness** | `~/.dsh` | ✅ | ✅ | 正文目录 + 元数据 + `workspace.json` 索引 + 附件（可选） |
| **WorkBuddy** | `~/.workbuddy/workbuddy.db` | ✅ | ✅ | `sessions` 行 + `session_usage` 行 + `VACUUM` 释放空间 |
| **CodeBuddy** | `~/.codebuddy`, `%LOCALAPPDATA%/CodeBuddyExtension` | ✅ | ✅ | 该会话在 4 棵树中的数据 + 项目 `index.json` 条目（**保留项目本身与其他会话**） |
| **GitHub Copilot Chat** | `%APPDATA%/Code/User/globalStorage` | ✅ | ✅ | `sessions`/`turns`/`checkpoints`/`session_files`/`session_refs` + **FTS5 全文索引** + jsonl 会话文件 + **`state.vscdb` 聊天列表索引** |
| **Antigravity Tools** | `~/.antigravity_tools` | ✅ | ✅ | `thinking_sessions` + `thinking_records`（**不碰** token 统计与安全日志） |

### VS Code 的两处隐形残留（已处理）

VS Code 的聊天数据分散在**三个**地方，后两处是肉眼看不见的：

```
%APPDATA%/Code/User/globalStorage/
  github.copilot-chat/session-store.db     会话行 + turns + checkpoints + FTS5 全文索引
  emptyWindowChatSessions/<会话id>.jsonl    会话正文
  state.vscdb                              chat.ChatSessionStore.index = 聊天列表
```

1. **FTS5 全文索引**：只删 `sessions` 行 → 已删对话**仍能被聊天搜索搜到**。
2. **`state.vscdb` 聊天列表索引**：只删 `.jsonl` 文件 → 聊天列表里**残留一个点不开的条目**。本机实测就存在这样一条（`agent-host-copilotcli:/untitled-…`，磁盘上已无文件）。

本工具两处都会清理，并且能**原样还原**（实测还原后索引 blob 与删除前**逐字节一致**）。

> 注意：VS Code 的会话 ID 可能包含 `:` 与 `/`（如 `agent-host-copilotcli:/untitled-…`）。这种 ID 作为「索引键」是合法的，但绝不能拼成文件名。因此本工具区分两类校验：`is_safe_session_id()` 用于会变成路径的 ID（严格），`is_safe_key()` 用于仅作键的 ID（允许 `:` 和 `/`，但仍拒绝 `..`、反斜杠、控制字符）。所有由 ID 推导出的**路径**都由执行器统一按 Agent 数据目录再做一次白名单校验。

### CodeBuddy 的层级陷阱（已处理）

CodeBuddy 的目录结构容易误判，实测结构为：

```
<account>/VSCode/<workspace>/
  history/<项目ID>/                 <- 项目容器，不是会话！
      index.json                    {"conversations":[{id,name,...}]}
      <会话ID>/index.json + messages/   <- 真正的会话
  check-point/<项目ID>/<会话ID>/
  file-tree/<项目ID>/<会话ID>/
  plan-task/<项目ID>/<会话ID>/
```

**若把 `history/<项目ID>/` 当成一个会话删除，会一次毁掉该项目下的全部对话。**
因此本工具把会话 ID 定义为 `<项目ID>~<会话ID>`，只删除该会话在四棵树中的目录与项目索引里的对应条目，**项目目录、同项目其他会话、以及不属于会话的检查点目录都不会被改动**（有专门的回归测试断言这一点，见 `selftest_sqlite.py` 第 11–15 项）。

未支持的 Agent（如 Claude Code、Codex CLI、Gemini CLI、Cursor）会在总览页列为「检测到但尚未支持」，**不会被扫描或修改**。新增一个 Agent 只需照 `adapters/dsh.py` 实现 `Adapter` 接口并注册到 `adapters/registry.py`。

---

## 调研结论：同类项目对比

对 GitHub 上 20+ 个同类项目做了调研（含 [orrery](https://github.com/arvelvale/orrery)、
[SessionSweep](https://github.com/xhkzdepartedream/SessionSweep)、
[session-steward](https://github.com/mallikcheripally/session-steward)、
[codeg](https://github.com/xintaofei/codeg)、
[myrlin-workbook](https://github.com/therealarthur/myrlin-workbook) 等）。

**三个能力最强的项目各自的长处**

| 项目 | 最值得学的设计 |
|---|---|
| **session-steward** | 删除计划 + 指纹校验 + **校验失败自动还原**，把破坏性操作做成事务；Keep 保护支持工作区级联 |
| **SessionSweep** | 明确「删除正文**和会让它复活的索引项**」；幽灵/孤儿/空白/重复 ID 四态标记；把折叠工具流量、只留人读的部分 |
| **orrery** | 持久化解析索引（按 `长度 + mtime` 增量重解析，冷启动 5.5s → 0.12s）；路径只由后端按 `(harness, id)` 解析；三语界面 |

**三者共同的空白**（也就是本工具的价值所在）

- **没有一个做正文全文检索**：都停在标题 / 路径 / 首条消息 / 会话 ID。
  想看「我到底在哪次对话里提过这个」是做不到的。
- **没有一个显示真实费用**：最多算 token 数。
- 各自只覆盖一部分：只有 session-steward 有保留保护与排程，只有 orrery 有界面国际化与终端恢复，
  只有 SessionSweep 有重复 ID 检测，而它**完全不支持 Windows**、删除**不可逆**。

**因此本工具的选择**：保留「先出计划 → 备份 → 执行 → 校验 → 可还原」的事务模型，
补上正文全文检索与用量核算，并且**不自动排程删除**——把执行权留给人。

---

```
agent-session-manager/
├─ server.py                 本地 HTTP 服务（仅监听 127.0.0.1）
├─ start.bat                 Windows 启动器
├─ run_all_tests.py          跑全部自测
├─ selftest_scan.py          P0 只读扫描 + 安全防护回归
├─ selftest_preview.py       会话内容预览（只读，逐字节校验）
├─ selftest_safety.py        保留标记 / 指纹校验 / 保留规则
├─ selftest_hostile.py       恶意会话 ID 防护
├─ selftest_delete.py        DSH 删除/还原（沙箱）
├─ selftest_sqlite.py        SQLite、FTS、VS Code 索引、CodeBuddy 层级（沙箱）
├─ selftest_realdb.py        真实数据库副本往返
├─ core/
│  ├─ util.py                路径、原子写、PowerShell、进程检测、安全删除
│  ├─ model.py               Session / Message / DeletePlan / DeleteAction
│  ├─ store.py               保留标记（会话级 + 工作区级）/ 标签 / 备注
│  ├─ search.py              正文全文检索索引
│  ├─ usage.py               token 用量与费用核算
│  ├─ retention.py           保留规则 + 价值评分（只建议，不执行）
│  ├─ export.py              会话导出（Markdown / 文本 / JSON）
│  ├─ inventory.py           统一扫描、健康检查、可回收项
│  └─ executor.py            事务化执行器（唯一有写权限的模块）
├─ adapters/
│  ├─ base.py                适配器接口（detect/list/plan/preview/verify）
│  ├─ registry.py            自动识别与总览报告
│  ├─ dsh.py / workbuddy.py / codebuddy.py
│  ├─ copilot_chat.py / antigravity.py
├─ web/index.html            前端界面（无构建步骤）
└─ _data/                    隔离区、操作日志（工具自身状态）
```

---

## 自测

```powershell
python run_all_tests.py
```

八个套件：

| 套件 | 覆盖 | 是否碰真实数据 |
|---|---|---|
| `audit_static.py` | 全模块导入、未定义名称、未使用导入 | 只读 |
| `selftest_scan.py` | 扫描全部 Agent、幽灵/孤儿识别、**运行中进程检测回归** | 只读 |
| `selftest_preview.py` | 预览解析（各种消息类型）、幽灵/空/云端/残留四种说明、恶意 ID 不致崩、**逐字节证明预览无写入** | **沙箱 + 真实数据只读** |
| `selftest_safety.py` | **保留标记（会话级 + 工作区级）阻止删除**、工作区路径边界（`test2` 不被 `test` 误伤）、显式覆盖、**指纹校验拒绝过期确认**、保留规则标注原因且不误报保留项、标签/备注往返 | **沙箱** |
| `selftest_hostile.py` | 5 个适配器 × 24 个恶意会话 ID（路径穿越、绝对路径、空字节、保留名等）→ **不得产生任何越界操作** | 只读 |
| `selftest_residue.py` | **归属分级**（safe/review/never）、**git 仓库绝不被清**（真实误删反例 `workbuddyapi-main`）、共享容器拒绝、凭据识别精度（真密钥报、打包运行时不报）、缓存 vs 有状态存储、**执行器纵深防御**、**预演零写入**、运行中进程门禁、数据根显式确认、隔离区保护期、**快捷方式真删且可还原**、**清理会计恒等式**（选中 = 已执行 + 已报告） | **沙箱** |
| `selftest_api.py` | **HTTP 层契约**：7 个破坏性接口全部支持 `dry_run` 且如实标注、**预演前后会话与隔离区逐项不变**、不可逆的卸载调用必须显式 `confirm`、畸形请求体被拒（4xx 而非静默成功） | 只读（只发预演请求） |
| `selftest_delete.py` | DSH 计划/删除/校验/还原、越界拒绝、活动会话保护、共享附件保护 | **沙箱** |
| `selftest_sqlite.py` | WorkBuddy 行删除与还原、Copilot 五张子表 + **FTS 索引**、VS Code 聊天索引、`VACUUM`、**CodeBuddy 项目层级保护** | **沙箱** |
| `selftest_realdb.py` | 用**真实数据库的副本**跑完整删除→校验→还原，逐表比对**每一行** | **只读原件**，只写副本 |

删除类测试在导入任何适配器**之前**就把 `USERPROFILE`/`APPDATA`/`LOCALAPPDATA` 指向临时沙箱，因此**不可能**碰到真实会话。`selftest_realdb.py` 只**读取**真实数据库并写入副本，且逐表比对往返前后每一行必须完全一致。

沙箱清理一律放在 `finally` 中：**测试崩溃也不留临时目录**。需要检查失败现场时设 `ASM_KEEP_SANDBOX=1` 保留沙箱。这条规则是被真实缺陷逼出来的——`selftest_residue.py` 曾在中途抛异常时泄漏沙箱（本机实测残留 7 个）。

关键断言包括：
- 删除后重扫 → **无幽灵、无孤儿**
- 删除共享附件所引用的会话后 → **其他会话的附件仍在**
- Copilot：删除前能搜到 → **删除后搜不到** → **还原后又能搜到**
- CodeBuddy：删除一个会话后 → **项目目录仍在、同项目其他会话仍在、非会话检查点仍在**；只传项目 ID 会被拒绝
- Copilot：`state.vscdb` 聊天列表索引中的**残留条目**（含含 `:`/`/` 的真实 ID）可被删除并**原样还原**
- 还原后状态与删除前**逐项一致**（真实库副本测试比对到**每一行**；索引 blob 还原后**逐字节相同**）
- 24 个恶意会话 ID × 5 个适配器 → **零越界操作**
- **预览会话内容前后，整个存储目录的哈希完全一致**（证明预览确实只读）
- **已标记「保留」的会话拒绝删除**；同一批里的其他会话不受影响
- **确认后内容若被改动，删除被取消**（指纹不匹配）
- **git 仓库（含仓库内的 Agent 目录）被判 `never`，预检与执行两层都拒绝，且执行后仓库完好**
- **含点文件名不会命中 reverse-DNS 规则**（`state.vscdb` 必须判 user_data，不能是 safe）
- **预演前后存储目录哈希一致，且不产生新的隔离区目录**
- **运行中：预演放行、真正执行拒绝、被拒后数据完好；显式 force 才可继续**
- **隔离区保护期内的条目，即使显式指定也不清除**
- 保留规则**只建议不执行**，且绝不把保留项列为候选
- 越界路径、活动会话、未知会话一律**拒绝**
- 全部套件运行后 **临时沙箱零残留**（防止"删不干净"的问题出现在本工具自己身上）

---

## 开发中修掉的真实缺陷

这些都是在测试中实际暴露出来的，记录在此以便回归：

| 缺陷 | 影响 | 位置 |
|---|---|---|
| 活动会话判定只看目录 mtime | DSH 追加写只更新**文件** mtime，正在运行的会话**不会被识别**，可能被删 | `adapters/dsh.py` `_newest_mtime` |
| `Get-Process` 返回无 `.exe` 名字 | 与适配器声明的 `"xxx.exe"` 不匹配 → **活动会话保护整体失效**且无任何报错 | `core/util.py` |
| PowerShell 写成 `pwsh` 且用 `repr()` 拼路径 | 子进程找不到 `pwsh`；`HKLM:\\SOFTWARE` 双反斜杠导致注册表**静默返回 0 条** | `core/util.py`, `adapters/registry.py` |
| CodeBuddy 把**项目**当会话 | 会一次删掉该项目下**全部对话** | `adapters/codebuddy.py` |
| 索引改写未备份 | 还原时无法回填索引条目 | `core/executor.py` |
| VS Code 会话 ID 含 `:`/`/` 被判为非法 | `state.vscdb` 中的残留条目**永远删不掉**（正是要清理的对象） | `core/util.py` `is_safe_key` |
| 未清理 `state.vscdb` 聊天列表索引 | 删了 `.jsonl` 但列表里仍留**点不开的条目** | `adapters/copilot_chat.py` |
| `dir_size` 未导入却被调用 | 潜在 `NameError`（死代码路径） | `adapters/registry.py` |
| `with sqlite3.connect(...)` 当关闭用 | Python 里它只提交事务、**不关闭句柄** → 备份文件在 Windows 上被锁住，隔离区**删不干净**（WinError 32） | `core/executor.py`, 两个适配器 |
| `rmtree(ignore_errors=True)` 吞掉失败 | 删除失败静默无感，留下空目录骨架（正是本工具要消灭的那类残留） | `core/util.py` `remove_tree` |
| 静态审计导入了 `selftest_*.py` | 这些是**程序**不是库，导入即创建沙箱却无人清理 → 每次审计泄漏临时目录 | `audit_static.py` |
| 含点的文件名被判成"反域名包" | `state.vscdb` 因文件名含点命中 reverse-DNS 规则，被判为**可再生缓存（safe）** → 会删掉 VS Code 状态库 | `core/ownership.py` `_REVERSE_DNS` |
| 适配器自己的数据根被判成缓存 | `github.copilot-chat` 是 Copilot 适配器的声明根，名字形如包名 → 被判 safe | `core/ownership.py`（exact 根的硬性回退：声明根永远不能是 safe） |
| 凭据识别按子串匹配 | 一个 704 MB 的 Agent 目录里报出 **150 个"密钥"**——`token.py`、`token-schema.json`、`user-secret.svg`、`git-credential-helper-selector.exe` 全部误报，真密钥被淹没 | `core/ownership.py`（改为：二进制硬排除 → 强名匹配胜过文档扩展名 → 分段+内容双重校验） |
| `~/.dsh` 整体判 `never` 掩盖内部残留 | 472 MB 浏览器缓存与 `.credentials.yaml` 全部不可见 | `core/ownership.py`（递归下钻：`never` 父目录内仍会列出可操作项） |
| `.credentials.yaml` 被扩展名排除漏掉 | `.yaml` 在"非凭据扩展名"表里，真密钥文件**漏报** | `core/ownership.py`（强名匹配先于扩展名排除） |
| 空目录被降级为"需确认" | 空目录不含任何文件，删除不可能丢数据，却被归属置信度降级挡住 | `core/ownership.py`（空壳一律 safe） |
| 预演被"Agent 正在运行"拦截 | 预演不改任何文件，却要求先退出程序——用户恰恰想在程序运行时先看看会删什么 | `core/cleaner.py`（预演始终放行，真正执行才检查进程） |
| 数据根目录因"归属不明"无法删除 | 完整卸载时适配器自己的根被判 `never`（分类器不认识该适配器） | `core/cleaner.py`（`allow_roots` 下按适配器自己的声明判定，shared/source_repo 仍拒绝） |
| 快捷方式被静默丢弃 | 选中后被排除在文件操作之外，又没有其他处理分支 → **既不删除也不报告**，界面却显示成功；只有需管理员的那几个因 `needs_admin` 侥幸出现 | `core/uninstall.py`（路由进文件执行器 + 新增 `accounting` 恒等式 + `reported` 列表） |
| 共享容器规则按任意路径段匹配 | `%APPDATA%\Microsoft\Windows\Start Menu\...` 含 "Microsoft" 和 "Windows" → **所有开始菜单快捷方式都被判 `never`**，永远清不掉 | `core/ownership.py`（`_shared_hit` 只看驱动符下前两层，`C:\Program Files`/`C:\Windows` 等仍然拦住） |
| 批量删除没有预演 | 批量是最危险的操作，却从"勾选"直接到"删除"，看不到哪些项会被安全检查拒绝 | `server.py` `/api/batch-delete` 支持 `dry_run`，前端确认框先展示预演结果 |
| **`/api/quarantine/purge` 忽略 `dry_run`** | 接口收了 `dry_run` 参数却**照样真的清空隔离区** —— 请求预演的调用方会丢掉自己的撤销缓冲。核心层测试抓不到这类缺陷（它们不经过 HTTP），为此新增 `selftest_api.py` | `server.py`（预演走 `plan_purge`）+ 新增 HTTP 契约测试套件 |
| 沙箱在测试崩溃时泄漏 | `selftest_residue.py` 只在 `main()` 末尾清理，中途抛异常就留下临时目录；`selftest_realdb.py` 更是**仅在全部通过时**才清理。本机实测残留 7 个沙箱 | 两个套件（清理移入 `finally`，`ASM_KEEP_SANDBOX=1` 可保留现场） |

---

## 已知限制

- **WorkBuddy / CodeBuddy 的对话正文在云端**，本地只有元数据，所以删除它们释放的空间很小，效果主要是清理列表。
- **Agent 版本升级可能改变存储格式**。遇到不认识的格式，适配器会降级为「仅浏览」而不是猜着删；需要时更新对应适配器。
- **删除前请退出对应的 Agent**。SQLite 类（WorkBuddy、Copilot）在应用运行时会被拒绝操作，因为程序持有数据库并在退出时重写。
- Antigravity Tools、Copilot 的会话表在当前机器上是空的，相关删除路径已在沙箱中验证，但**尚未在真实数据上跑过**。
- **`HKLM` 注册表键与防火墙规则需要管理员**。本工具不会尝试提权，而是给出可直接复制的命令。
- **调用官方卸载器不可撤销**。这是整个流程里唯一真正不可逆的一步，UI 要求勾选确认框，CLI 要求 `--yes`。
- **重复内容检测与敏感信息扫描只报告，不删除**。处置由用户在审阅后决定。
- 占用增长趋势需要多次快照才有效：少于 3 个数据点时明确提示数据不足，而不是给出误导性预测。

---

## 安全提示

- 服务**只绑定 `127.0.0.1`**，并设置 `X-Frame-Options: DENY`、`nosniff`。
- 代码中**没有任何外部网络请求**。
- 永久删除模式会直接 `rmtree` 隔离区，**不可还原**，请谨慎勾选。

---

## 维护提示：不要用 PowerShell 改这个文件

`web/index.html` 是 UTF-8 中文文件。**不要用 `Get-Content` / `Set-Content` 往返改写它**：
Windows PowerShell 5.1 的 `Set-Content` 默认按 ANSI 代码页写回，
会把中文替换成 `?` 从而**永久损坏文件**（本次开发中已踩过一次，损坏 178 处，
因无 git 备份只能重写整份界面）。

安全做法：用编辑工具（保留 UTF-8 无 BOM）修改，或用 Python：

```python
import pathlib
p = pathlib.Path("web/index.html")
t = p.read_text(encoding="utf-8")
p.write_text(t.replace("旧", "新"), encoding="utf-8")
```

仓库目前**没有版本控制**。建议首次提交前先 `git init`，这样界面改坏了可以回退。
