# Agent 会话清理工具 —— 调研、可行性分析与实施方案

> 目标：做一个本地可视化工具，**自动识别**电脑上装了哪些 Agent，**统一浏览**它们的会话，并能**安全删除**这些会话（含索引残留），解决 C 盘会话文件夹堆积、删不干净的问题。

日期：2026-10-05 ｜ 工作目录：`E:\AgentSessionManagement`

---

## ✅ 实施状态（2026-10-05 更新）

**方案 D（自建本地 Web 工具）已落地并通过验证**，代码位于 `E:\AgentSessionManagement\agent-session-manager\`。

| 阶段 | 状态 | 说明 |
|---|---|---|
| P0 自动识别 + 只读扫描 | ✅ 完成 | 5/5 Agent 自动识别，15 个会话（含幽灵/孤儿标记） |
| P1 干跑删除计划 | ✅ 完成 | 每个会话可预览将改动的每个文件/数据库行 |
| P2 安全删除（事务化） | ✅ 完成 | 隔离区 + 备份 + 事后校验 + 一键还原 |
| P3 扩展适配器 | ✅ 完成 | DSH / WorkBuddy / CodeBuddy / Copilot / Antigravity 全部支持删除 |
| P4 清理建议 + 界面 | ✅ 完成 | 幽灵/孤儿/无引用附件/空目录/软删除残留/可回收空间 |

**自测：3 个套件全部通过**（`python run_all_tests.py`），其中删除类测试在沙箱中进行，不可能触碰真实数据。

**测试中发现并修复的真实缺陷：**

1. **CodeBuddy 把「项目」当成「会话」** —— 最严重。`history/<项目ID>/` 是项目容器（内含 `conversations` 数组），原实现会把整个项目连同其下**全部对话**一次删掉。已改为以 `<项目ID>~<会话ID>` 标识会话，并加了专门的回归断言。
2. **活动会话保护失效** —— `Get-Process` 返回不带 `.exe` 的进程名，与适配器声明的 `"xxx.exe"` 不匹配，导致"会话正在运行"检测**静默失效**。已统一两种写法，并加了回归测试。
3. **活动判定只看目录 mtime** —— DSH 追加写只更新**文件** mtime，正在运行的会话会被漏判。已改为递归取最新文件时间。
4. **PowerShell 调用不可用** —— 子进程找不到 `pwsh`（本机只有 Windows PowerShell 5.1），且用 `repr()` 拼注册表路径产生 `HKLM:\\SOFTWARE` 双反斜杠，导致注册表查询**静默返回 0 条**。已改为解析可用的 PowerShell 并用 `-EncodedCommand` 传参。
5. **还原无法回填索引** —— JSON 索引改写前未备份。已改为记录移除位置并原样回填。

**完整说明与使用方式见 [agent-session-manager/README.md](agent-session-manager/README.md)。**

---

## 一、结论先行

1. **GitHub 上有大量同类项目，但没有任何一个同时满足你的四个要求。** 现有项目要么能跨 Agent 浏览但**不能删**，要么能安全删但**只支持 1～2 个 Agent**，要么删得动但**只有 TUI 没有界面**，要么是 **macOS 专属**。
2. **市场空缺非常明确**：一个 **Windows 优先 + 图形界面 + 多 Agent 自动识别 + 删会话连索引一起删（带预览/备份/撤销）** 的工具，目前不存在。
3. **更关键的发现**：现有开源项目几乎都盯着 `~/.claude`、`~/.codex` 这类 **CLI 工具的点目录**，而**你这台电脑上一个 CLI Agent 都没装** —— 你装的全是 **GUI 桌面应用**（DSH、WorkBuddy、CodeBuddy、VS Code Copilot）。**照搬现有项目的适配层，在你机器上几乎匹配不到任何东西。** 这既是坑，也正是自建的价值所在。
4. **能删干净吗？能，但必须"事务化删除"。** 我已在你机器上**实测到真实的"幽灵会话"残留**（详见第四节），证明"只删文件夹"这条路一定会留下删不干净的垃圾。技术上完全可行，前提是把"文件 + 索引 + 数据库 + 附件引用计数"作为一个整体处理。

**建议路线：自建一个轻量本地 Web 工具（Python 后端 + 浏览器界面），把删除逻辑做成"先出计划 → 备份 → 执行 → 校验 → 可还原"。** 理由见第六节。

---

## 二、GitHub 同类项目调研

### 2.1 最相关的 5 个项目

| 项目 | ★ / 最近提交 | 语言·协议 | 支持的 Agent | 能否删会话 | 界面 | Windows |
|---|---|---|---|---|---|---|
| [arvelvale/orrery](https://github.com/arvelvale/orrery) | 37 · 2026-09-28 | Rust/Tauri · MIT | Claude Code、Kimi、**DSH**、Codex、OpenCode、Antigravity、Z Code\*、WorkBuddy\* | **能**：删对话文件 **+ 索引**，默认进回收站，有备份 | Tauri 桌面 + 浏览器 | **Win10/11 一等公民** |
| [xhkzdepartedream/SessionSweep](https://github.com/xhkzdepartedream/SessionSweep) | 1 · 2026-10-01 | Python · MIT | Claude Code、Codex、**DSH**、Pi | **能**（删除逻辑最严谨）：同时清掉"会让会话复活的索引项" | **仅 TUI** | 跨平台，无 AppData |
| [mallikcheripally/session-steward](https://github.com/mallikcheripally/session-steward) | 4 · 2026-09-24 | Node · MIT | **仅 Codex、Claude** | **能**：可审阅计划 → 备份 → 删除 → 校验 → 还原 | **浏览器界面** | **Win/mac/Linux** |
| [lucascaro/hive](https://github.com/lucascaro/hive) | 11 · 2026-10-05 | TS+Go · MIT | Pi、Claude、Codex、Gemini、Copilot、Aider、OpenCode | **不能** | 桌面 GUI | 未明确 |
| [therealarthur/myrlin-workbook](https://github.com/therealarthur/myrlin-workbook) | 386 · 2026-09-29 | JS · AGPL-3.0 | Claude、Codex | **不能**（明确"只读，不持有写句柄"） | Web + 手机 | **Win 一等公民** |

\* 只读支持。

### 2.2 其他有参考价值的项目

| 项目 | ★ | 要点 |
|---|---|---|
| [xintaofei/codeg](https://github.com/xintaofei/codeg) | 3795 | 支持 **14 种** Agent（含 DSH、CodeBuddy、Cursor、Antigravity），但**没有删除** |
| [kbwo/ccmanager](https://github.com/kbwo/ccmanager) | 1258 | 有 **win32-x64** 构建，但只删自己的记录，TUI |
| [jazzyalex/agent-sessions](https://github.com/jazzyalex/agent-sessions) | 890 | 支持 9 种 Agent，**仅 macOS** |
| [voidcraft-dev/memory-forge-rs](https://github.com/voidcraft-dev/memory-forge-rs) | 492 | 编辑/擦除**消息**，不是删会话；用 `%APPDATA%\Cursor\User` |
| [1939869736luosi/codex-sessions-manager](https://github.com/1939869736luosi/codex-sessions-manager) | 13 | **删除安全性最强**：计划/垃圾桶/还原/校验/日志/回滚、只认精确 UUID、拒绝活动会话。但**仅 Codex**，且 **Windows 上删除操作主动"失败关闭"（只读）** |
| [Atituiset/agent-viewer](https://github.com/Atituiset/agent-viewer) | 0 | **明确只读**（"绝不修改会话文件"），Win/mac/Linux + SSH + WSL |
| [seastart/aicoder-session-viewer](https://github.com/seastart/aicoder-session-viewer) | 11 | 明确覆盖 `%USERPROFILE%\.claude\projects`、`.codex\sessions`、`.gemini\tmp`、`%APPDATA%`，但无删除 |
| [izll/agent-session-manager-desktop](https://github.com/izll/agent-session-manager-desktop) | 23 | Windows（psmux）桌面 GUI，回收站删的是**自己的**条目，不是会话记录 |
| [AndyWipe13/dsh-session-management](https://github.com/AndyWipe13/dsh-session-management) | 2 | **DSH 原生插件**，可删 DSH 会话，并能从 Claude/Codex 导入 |
| [vyagh/reap](https://github.com/vyagh/reap) | 2 | Claude + Codex 清理，可预览 |
| [KenCheung-AIxFinance/claude-code-session-manager](https://github.com/KenCheung-AIxFinance/claude-code-session-manager) | 10 | 仅 Claude，CLI+TUI，能删 |

（以上项目均无归档，头部项目在 2026-10-05 前后 10 天内都有提交，说明这是个正在升温的赛道。）

### 2.3 全行业共同缺失的能力

**没有任何一个项目同时具备这四点：**

1. 广泛的跨 Agent 自动识别（≥5 种，且覆盖新式 Agent）
2. **安全删除** = 会话文件 **+ 会让它"复活"的索引项**，且带 干跑计划 / 备份·回收站 / 撤销还原 / 运行中保护
3. **图形界面**（不是只有 TUI/CLI）
4. **Windows 原生路径优先**与验证

各项目的缺口刚好互相错开：
- `SessionSweep` 有 ①②④，**没界面**
- `orrery` 有 ①③④，能删，但**是 37★ 的早期原型，删得比较"粗"**（没有干跑计划、没有撤销日志，只有"进回收站"或"永久删除"两档）
- `session-steward` 有 ②③④，但**只有 2 种 Agent**
- `codeg` / `myrlin` / `agent-viewer` / `agent-sessions` / `monet` / `hive` 有 ①③，**完全不能删会话**
- `codex-sessions-manager` 删除最安全，但**仅 Codex，且在 Windows 上直接拒绝删除**

### 2.4 被普遍忽略的"幽灵会话"陷阱

**只删对话文件、不删索引 = 留下一个点开就报错的僵尸条目。** 只有 `SessionSweep`、`orrery`、`codex-sessions-manager` 三个项目专门处理了这件事（要清 Codex 的 `threads` 表、DSH 的 `workspace.json`、Claude 的 `history.jsonl` 等）。这正是你说的"删不干净"的根因。

---

## 三、本机实测：到底装了什么、东西在哪

> 以下为 2026-10-05 实际扫描结果，非推测。

### 3.1 已安装的 Agent（注册表 + 目录双重确认）

| Agent | 类型 | 会话/数据位置 | 体积 |
|---|---|---|---|
| **DeepSeek Harness (DSH) 0.2.0-rc.2** | 桌面应用 | `%USERPROFILE%\.dsh\` | **355 MB** |
| **WorkBuddy 5.6.2** | 桌面应用 | `%USERPROFILE%\.workbuddy\` + `%APPDATA%\WorkBuddy` | **704 MB** |
| **CodeBuddy**（腾讯，VSCode 插件系） | 插件 | `%USERPROFILE%\.codebuddy\` + `%LOCALAPPDATA%\CodeBuddyExtension\` | 78 MB |
| **GitHub Copilot Chat**（VS Code） | 插件 | `%APPDATA%\Code\User\globalStorage\github.copilot-chat\` | 0.2 MB |
| **VS Code 内置 Chat** | 编辑器 | `%APPDATA%\Code\User\globalStorage\emptyWindowChatSessions\` | 极小 |
| **Antigravity Tools 4.9.0** | 桌面应用（代理） | `%USERPROFILE%\.antigravity_tools\`（5 个 SQLite） | 0.3 MB |

**重要：`~/.claude`、`~/.codex`、`~/.gemini`、`~/.cursor`、`~/.aider` 等全部不存在** —— 本机**没有任何 CLI 编码 Agent**，`npm ls -g` 只有 npm/corepack 本身，PATH 上找不到 claude/codex/gemini/copilot/opencode/aider 任何一个。

> **这是本次调研最有价值的发现**：GitHub 上的工具绝大多数把适配层写死在 `~/.claude`、`~/.codex` 上。**在你的机器上，它们大部分会发现"0 个 Agent"。** 可用的只有 `orrery`（支持 `.dsh`，WorkBuddy 只读）和 `SessionSweep`（支持 `.dsh`），而且都不认识 WorkBuddy/CodeBuddy/Copilot 的存储格式。

### 3.2 一个 DSH 会话其实散落在 4 个地方

| 位置 | 内容 | 删除时的影响 |
|---|---|---|
| `.dsh\sessions\<工作区>\<会话id>\session.v4.jsonl.zstd` | 对话正文（zstd 压缩） | 删了正文 |
| `.dsh\storages\session_projcache\sessions\<会话id>.json` | 标题、首条提问、目标等**元数据** | 不删 → **侧边栏残留幽灵条目** |
| `.dsh\storages\workspace.json` | 工作区 → `sessionIds` 数组 | 不删 → **会话"复活"或列表错乱** |
| `.dsh\attachments\v1\objects\<aa>\<hash>` | 图片等附件，**内容寻址、多会话共享** | 盲删 → **破坏其他会话的附件** |

### 3.3 实测抓到的真实残留（可复现）

```
=== 磁盘上的 DSH 会话目录 (7) ===
=== projcache 元数据条目 (8) ===
=== workspace.json 里的 sessionIds (4) ===

>>> 幽灵：projcache 有条目、但会话目录不存在
    session-2aad195e-ba28-4ef3-a074-f0edbb85eef2   ← 就是"删文件夹没删干净"的现场

>>> 孤儿：会话目录存在、但不在 workspace.json 里（3 个）
    session-e8a8366c-...、3d4f003e-...、session-fcd4e0b9-...
```

**这直接证明了你的判断是对的**：会话数据是**多副本、互相引用**的，手工删文件夹必然留下不一致的残渣。

### 3.4 其他 Agent 的存储形态（决定了适配器怎么写）

- **WorkBuddy**：SQLite `%USERPROFILE%\.workbuddy\workbuddy.db`，`sessions` 表 **40 个字段**，含 `deleted_at`（**软删除**语义，当前 3 行全是 `-1` = 未删）。删会话要同时处理：DB 行、`session_usage`、以及可能存在的磁盘正文。另外 `%APPDATA%\WorkBuddy` 下还留着**旧版 `codebuddy-sessions.vscdb` 迁移痕迹**（已 skipped）。
- **CodeBuddy**：`.codebuddy` 只有 `expert-history.json` + 记忆文件，正文可能在 `%LOCALAPPDATA%\CodeBuddyExtension\Data\<用户id>\VSCode` 下的 VS Code 存储里。
- **Copilot Chat**：SQLite `session-store.db`，`sessions` / `turns` / `checkpoints` / `session_files` / `session_refs` / `search_index`（FTS5 全文索引）…… **删会话要连 FTS 索引一起清**，否则搜索里还能搜到已删内容。当前表全空。
- **Antigravity Tools**：`thinking_store.db`（`thinking_sessions` / `thinking_records`）等 5 个库，当前全空。它是**代理**，会话量取决于是否真正使用。

### 3.5 顺带发现的可回收空间

| 项目 | 大小 | 说明 |
|---|---|---|
| `%LOCALAPPDATA%\@genieworkbuddy-desktop-updater\installer.exe` | **506 MB** | 升级残留安装包 |
| `%LOCALAPPDATA%\@deepseek-aidsh-desktop-updater\installer.exe` | **276 MB** | 升级残留安装包 |
| `%LOCALAPPDATA%\Tabbit Browser` + `TabbitBrowser` | 891 MB | 浏览器数据（非 Agent） |
| `%APPDATA%\Tencent` / `ACLOS` | 907 MB / 322 MB | 非 Agent |

> C 盘当前 41.6 GB 已用 / 357 GB 可用，**目前并不紧张**；但会话类数据的增长是持续的，早点上工具是对的。

---

## 四、可行性分析

### 4.1 技术可行性：**高**

| 能力 | 可行性 | 依据 |
|---|---|---|
| 自动识别装了哪些 Agent | **高** | 三路交叉验证：注册表 Uninstall 键 + 已知目录探测 + 进程/PATH 探测。DSH、WorkBuddy、Antigravity 都能从注册表拿到 `InstallLocation`。 |
| 统一列出会话 | **中高** | 每个 Agent 写一个适配器：DSH 读 jsonl.zstd + projcache；WorkBuddy 读 SQLite；Copilot 读 SQLite+FTS。格式已全部摸清。 |
| 安全删除 | **高（需事务化）** | 见 4.2。 |
| 图形界面 | **高** | 本地 Web 界面即可，无需 Electron/Tauri。 |
| 恢复到删除前 | **高** | 删除前把"要动的每个文件"整体搬进隔离区（或系统回收站），并落一份 JSON 操作日志。 |

### 4.2 删得干净的关键：事务化删除

难点不在"删文件"，而在**跨存储的一致性**。删除一个会话必须是：

```
1. 解析   ：按会话 id 找出它的全部落点（正文 + 元数据 + 索引 + 附件引用）
2. 出计划 ：打印/展示将改动的每个路径（干跑 dry-run）
3. 校验   ：确认路径在预期根目录内、会话当前未被运行中的进程占用
4. 备份   ：整体移入隔离区 + 写 JSON 操作日志（含原子写：临时文件 + rename）
5. 执行   ：文件夹用回收站；SQLite 用 BEGIN IMMEDIATE 事务；JSON 索引用临时文件+rename
6. 引用计数：附件是共享的，只有在没有任何会话引用时才回收
7. 校验结果：重新扫描，确认无幽灵、无孤儿
8. 可还原 ：按日志一键回滚
```

**必须防的 5 个坑**（都已在真实项目里被踩过）：
1. **幽灵条目** —— 删正文不删索引（本机已实测到）
2. **活动会话** —— 正在运行的会话被删，导致程序崩溃或数据损坏（要探测进程 / 文件锁）
3. **共享附件** —— 内容寻址的附件被误删，连累其他会话
4. **软删除** —— WorkBuddy 的 `deleted_at` 是软删除，只把行标成删除并不释放空间，必须真正 vacuum/清行
5. **写坏数据库** —— `.db-wal` / `.db-shm` 存在时改动有风险，必须先确认 Agent 已退出

### 4.3 风险与限制

| 风险 | 等级 | 应对 |
|---|---|---|
| 各 Agent 版本升级改存储格式 | **高** | 适配器要**容错**：格式不符就降级为"只读浏览 + 提示"，绝不猜着删 |
| 误删用户重要对话 | 高 | 默认进回收站/隔离区，永不默认永久删除；删除前强制预览 |
| 破坏正在运行的 Agent | 中 | 改动前检查进程；要求先关掉对应 Agent |
| 抓取会话正文涉及隐私 | 中 | **完全本地、零联网、零遥测**；正文默认只在本地显示 |
| 逆向了闭源应用的私有格式 | 中 | 只依赖已实测的格式；写成插件式，坏了单独修 |

---

## 五、推荐方案

### 5.1 形态选择

| 方案 | 说明 | 评价 |
|---|---|---|
| A. 直接用现成的 | 装 `orrery` 试试 | 最快，但**本机 4 个 Agent 里它只认 DSH**，WorkBuddy/CodeBuddy/Copilot 都不支持，且删得不够稳 |
| B. 只用 `SessionSweep` | Python CLI，删得最严谨 | 支持 `.dsh`，但**没界面**、只覆盖 4 种 Agent、不认 WorkBuddy |
| C. 给 DSH 写插件 | 参考 `dsh-session-management` | 只在 DSH 内可用，管不到其他 Agent |
| **D. 自建本地 Web 工具（推荐）** | Python 后端 + 浏览器界面，插件式适配器 | **唯一能完全满足四个要求**；可先只做 DSH + WorkBuddy，再逐步加 |

**推荐 D**，理由：
1. 现有工具的适配层在本机**基本失效**（没有 `.claude`/`.codex`），必须自己写适配器；
2. 你真正需要的核心能力是**删得干净**，而这恰好是现有 GUI 工具最弱、最容易出错的地方，自己掌控更安全；
3. 本地 Web 界面开发成本最低，且天然跨平台；
4. 可以先做**只读浏览**（零风险）验证适配器，再加删除能力。

### 5.2 技术选型

- **后端**：Python 3.14（本机已有）+ FastAPI/Flask，仅监听 `127.0.0.1`
- **前端**：单页 HTML + 少量 JS（无需构建链）
- **数据**：不引入数据库，每次实时扫描（会话量不大）；操作日志用 JSONL
- **删除**：`send2trash`（系统回收站）为默认；隔离区模式给"可一键还原"
- **安全**：路径白名单校验（防止路径穿越）、运行中进程检测、干跑预览

### 5.3 架构

```
agent-session-manager/
├─ server.py                 # 本地 HTTP 服务 + API
├─ core/
│  ├─ registry.py            # 探测：谁装了？数据在哪？
│  ├─ inventory.py           # 统一扫描 → 会话列表
│  ├─ planner.py             # 删除计划（dry-run）
│  ├─ executor.py            # 事务化执行 + 操作日志
│  └─ restore.py             # 从日志/隔离区还原
├─ adapters/                 # 每 Agent 一个文件，插件式
│  ├─ base.py                # 接口：detect/list/plan_delete/verify
│  ├─ dsh.py                 # 正文 + projcache + workspace.json + 附件引用计数
│  ├─ workbuddy.py           # SQLite sessions 表 + 软删除 + session_usage
│  ├─ copilot_vscode.py      # session-store.db + FTS 索引
│  ├─ codebuddy.py           # .codebuddy + CodeBuddyExtension
│  ├─ antigravity.py         # thinking_store.db
│  └─ _template.py           # 新 Agent 的模板
└─ web/                      # 界面
```

**适配器统一接口**：
```python
class Adapter:
    name: str
    def detect(self) -> bool                    # 本机是否安装
    def roots(self) -> list[Path]               # 数据根目录（用于白名单校验）
    def list_sessions(self) -> list[Session]    # 会话列表（含大小/时间/标题/工作区）
    def plan_delete(self, sid) -> DeletePlan    # 将改动的每个路径 + 理由 + 影响
    def verify_absent(self, sid) -> bool        # 删除后校验：无幽灵、无孤儿
```

### 5.4 界面要点

- **总览**：每个 Agent 一张卡（图标 / 已安装 / 会话数 / 占用空间 / 最后活动）
- **会话列表**：按 Agent、工作区、时间、体积筛选；可按体积排序找"最占地方的"
- **删除**：勾选 → 弹出**变更清单**（逐个文件路径 + 是否可还原）→ 确认 → 执行 → 结果校验
- **安全闸门**：默认回收站；永久删除需要额外勾选二次确认；检测到 Agent 在运行就拦下
- **清理建议**：识别残留安装包、空白会话、孤儿会话、超期会话，一键出建议（不自动执行）

### 5.5 分阶段实施计划

| 阶段 | 内容 | 产出 | 风险 |
|---|---|---|---|
| **P0 只读扫描**（0.5～1 天） | `registry.py` + `dsh.py` + `workbuddy.py`；网页只列会话、能看大小/标题/时间，**不能删** | 能看清全机器会话分布 | **零风险** |
| **P1 干跑计划**（0.5～1 天） | `planner.py`；每个会话给出"删它会动哪些文件"的清单，只打印不执行 | 用真实数据验证删除逻辑正确 | 零风险 |
| **P2 安全删除**（1 天） | `executor.py` + 回收站 + 操作日志 + 删除后校验；先只在 **DSH** 上启用 | DSH 会话能一键干净删除并可还原 | 中，有备份 |
| **P3 扩展适配器**（每个 0.5 天） | WorkBuddy → Copilot/VS Code → CodeBuddy → Antigravity | 覆盖本机全部 Agent | 中 |
| **P4 体验完善**（1 天） | 清理建议、孤儿/幽灵检测、批量操作、筛选排序 | 好用的日常工具 | 低 |
| **P5 可选**（按需） | 支持 CLI Agent（`.claude`/`.codex`/`.gemini`）、跨机导出、打包成 exe | 通用工具 | 低 |

**总计约 4～6 天可达到"本机全 Agent 可视化 + 安全删除"。**

### 5.6 验收标准（可执行）

1. 扫描结果与手工核对一致：DSH 7 个会话、WorkBuddy 3 个会话等
2. 删掉一个 DSH 会话后，重扫结果**无幽灵、无孤儿**（projcache 与 workspace.json 同步清理），DSH 侧边栏不再出现该会话
3. 删除后能从隔离区**一键还原**，且还原后会话可正常打开
4. Agent 正在运行时，删除被正确拦截
5. 共享附件：删除一个引用该附件的会话后，**其他会话的图片仍能打开**
6. 全过程**零联网**（可用网络监控验证）

---

## 六、另外值得一提的两件事

1. **顺手省 782 MB**：`%LOCALAPPDATA%\@genieworkbuddy-desktop-updater\installer.exe`（506 MB）和 `@deepseek-aidsh-desktop-updater\installer.exe`（276 MB）是升级残留的安装包，可直接删。工具里应该内置这类"清理建议"。

2. **本会话开始时遇到并已修复的问题**：工作区 `E:\AgentSessionManagement` 的 Windows 文件权限不完整（缺少 WRITE_OWNER），导致所有命令都被拒绝。已用 DSH 自带的诊断脚本修复并验证通过。备份与回滚命令在：
   - 报告：`E:\AgentSessionManagement\acl-recovery\acl-report-9688a8d769374446b3bf0691a229a7fd.jsonl`
   - 回滚：`pwsh -NoProfile -File 'E:\AgentSessionManagement\acl-recovery\acl-backup-cb5da7b86a7141469335a3443c0e1a7a.json.ps1' -Path 'E:\AgentSessionManagement' -AllowRoot 'E:\AgentSessionManagement' -Restore 'E:\AgentSessionManagement\acl-recovery\acl-backup-cb5da7b86a7141469335a3443c0e1a7a.json'`

---

## 七、下一步（等你确认）

请选择要走的路线：

- **A. 开始建**：从 P0 只读扫描做起，我先做出"能看到本机所有 Agent 会话"的版本，你验证后再逐步加删除能力（推荐）
- **B. 先试现成的**：我先帮你把 `orrery` 装起来试试，感受一下它对你机器（大概率只认 DSH）的覆盖度
- **C. 只做 DSH**：缩小范围，先彻底解决 DSH 会话的浏览与清理
- **D. 先清空间**：先处理那 782 MB 残留安装包和明显的垃圾，工具稍后再做

> 本机扫描未做任何修改（仅新增了本方案文档与 ACL 修复所需的备份文件）。
