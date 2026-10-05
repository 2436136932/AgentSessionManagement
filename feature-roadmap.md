# Agent 会话管理器 — 功能扩展计划

> 本文基于对**本机 5 个 Agent 的实际测量**（2026-02，非推测）。所有数字都是扫出来的，不是估的。

---

## 0. 先说一个反直觉的实测结论

我算了每个 Agent「会话数据」与「总占用」的账：

| Agent | 会话字节 | 总足迹 | 会话占比 | 会话数 |
|---|---:|---:|---:|---:|
| DeepSeek Harness | 7.7 MB | 740.6 MB | **1.0%** | 10 |
| WorkBuddy | 0.0 MB | 704.4 MB | **0.0%** | 3 |
| CodeBuddy | 5.6 MB | 54.6 MB | 10.3% | 3 |
| Copilot Chat | 0.0 MB | 2.1 MB | 0.1% | 2 |
| Antigravity | 0.0 MB | 0.4 MB | 0.0% | 0 |
| **合计** | **13.3 MB** | **1,502 MB** | **0.9%** | 18 |

再把安装目录算进来：`E:\DeepSeek Harness` 1,015 MB + `E:\WorkBuddy` 1,348 MB + `E:\Antigravity Tools` 57 MB = **2,421 MB**。

**全机 Agent 相关占用约 3.9 GB，会话只占 13.3 MB（0.34%）。**

所以「清会话」是个**整洁度**功能，不是**腾空间**功能。真正的大头是：

```
E:\WorkBuddy                       1,348 MB   安装目录
E:\DeepSeek Harness                1,015 MB   安装目录
~/.dsh/web-login/transport-profile   472 MB   ← 浏览器内核 + 组件缓存
~/.workbuddy/binaries                483 MB   ← 内置二进制
~/.dsh/profiles/desktop              258 MB   ← 主要是 node_modules
~/.workbuddy/plugins                 147 MB   ← 插件
~/.workbuddy/logs                      5.8 MB
```

你现在要的「彻底清理干净」，恰好打在这个真问题上。而且现有的会话级删除**永远碰不到**这些路径——因为 `roots()` 只声明了 `~/.dsh`、`~/.workbuddy` 这类数据根，且执行器的白名单会拒绝任何非 adapter 生成的路径。

---

## 1. 现状缺口（实测，不是猜）

### 1.1 「可回收空间」功能在本机 0 命中

`core/inventory.py` 里的 `RECLAIMABLE_HINTS` 硬编码了两条：

```python
"@genieworkbuddy-desktop-updater"      # 实测：不存在
"@deepseek-aidsh-desktop-updater"      # 实测：不存在
```

`reclaimable()` 返回 `[]`。这个功能目前是**死代码**。

### 1.2 工具完全没覆盖的真实残留（本机实测存在）

| 路径 | 大小 | 性质 | 风险 |
|---|---:|---|---|
| `~/.workbuddy-key-fallback/connector-keys/*.key` | 1 文件 | **密钥材料** | 安全敏感 |
| `%APPDATA%/@deepseek-ai/dsh-desktop` | 33.9 MB | Electron 缓存 | 低 |
| `%LOCALAPPDATA%/com.lbjlaq.antigravity-tools` | 32.7 MB | WebView2 缓存 | 低 |
| `%LOCALAPPDATA%/CodeBuddyExtension` | 30.2 MB | 扩展数据 | 中 |
| `%LOCALAPPDATA%/copilot` | 2 文件 | 空壳 | 低 |
| `~/WorkBuddy/Claw` | 1 目录 | 空壳 | 低 |
| `%APPDATA%/WorkBuddy` | 空 | 空壳 | 低 |
| `E:\WorkBuddyStorage` | 空 | 空壳 | 低 |
| `%TEMP%/dsh-*` × 7 | — | 临时目录 | 低（部分在用） |

加上注册表与系统集成：

- `HKCU\SOFTWARE\lbjlaq\Antigravity Tools`
- `HKCU\SOFTWARE\Tencent\*`（5 个子键，但**与 QQ/微信共享**，不能整体删）
- 防火墙规则 `WorkBuddy editor_sdk` 入站/出站 各 1 条
- 开始菜单快捷方式 3 个（可反查安装位置）

### 1.3 卸载入口其实拿得到，工具没用

实测注册表里都有 `QuietUninstallString`：

```
DeepSeek Harness 0.2.0-rc.2 → "E:\DeepSeek Harness\Uninstall DeepSeek Harness.exe" /currentuser /S
WorkBuddy 5.6.2              → "E:\WorkBuddy\Uninstall WorkBuddy.exe" /allusers /S
Antigravity Tools 4.9.0      → (无静默参数，只有 uninstall.exe)
```

`adapters/registry.py` 的 `installed_programs()` 已经读了 `InstallLocation`，**但没读 `UninstallString` / `QuietUninstallString`**，也没读 `DisplayIcon`、`EstimatedSize`。加几个字段就能支撑卸载向导。

### 1.4 当前进程**未提权**

```
elevated: False    user: DESKTOP-OL941JU\admin
```

意味着：删 `HKCU` 键可以；删 `HKLM` 键、删防火墙规则**会失败**。计划里必须把「需要管理员」显式告知，而不是静默失败。

### 1.5 一个必须防住的误删反例（本机真实存在）

```
E:\workbuddyapi-main    ← 用户自己的 git 仓库，含 .git 和源码
  └─ 里面有一个 .codebuddy 目录（Agent 曾在此工作）
```

任何「按关键词扫盘」的残留清理都会命中它。**它绝不能删。** 这就是为什么残留清理必须是「规则 + 证据 + 分级」，而不是「名字匹配」。

### 1.6 隔离区没有过期机制

`_data/quarantine/` 目前为空，但代码里**没有任何保留期或容量上限**。删一次大目录（比如 483 MB 的 `binaries`）就会永久躺在隔离区。这是 P1 必须补的洞。

---

## 2. 计划：分四批

按「你原话里最想要的」排序，不是按实现难度排序。

### 第 0 批 — 先修地基（不做完，后面全是空中楼阁）

| # | 功能 | 解决什么 | 实现要点 |
|---|---|---|---|
| 0.1 | **`PathOwnership` 归属模型** | 现在只有 `roots()` 一个粗粒度白名单，无法表达「这个路径属于哪个 Agent、置信度多少」 | 新增 `core/ownership.py`：路径 → `(agent_id, confidence, category)`。三级：`exact`（注册表/包名精确推导）、`heuristic`（命名规律）、`unknown`（不确定，永不自动删） |
| 0.2 | **隔离区保留策略** | 隔离区无上限、无过期 | `_data/quarantine/` 加：默认保留 7 天、总量上限（如 2 GB）、超限时按 LRU 提示。加「清空隔离区」按钮 + 保留期设置 |
| 0.3 | **共享资源保护表** | 防误删 QQ/微信共用的 `HKCU\SOFTWARE\Tencent`、共享运行时 | 显式黑名单：`Tencent`（部分）、`Microsoft`、运行库目录；命中即标记 `never` |
| 0.4 | **API 层加操作预演** | 现在所有写操作都是「直接干」 | 所有清理类 API 增加 `dry_run` 参数，先返回**逐条动作 + 预计释放字节 + 置信度**，用户确认后再执行 |
| 0.5 | **管理员权限降级提示** | 未提权时删 HKLM/防火墙会静默失败 | 预检阶段探测每个动作是否需要提权，UI 明确标注「需管理员」，不尝试后报错 |

### 第 1 批 — 你真正要的「彻底卸载干净」

| # | 功能 | 解决什么 | 实现要点 |
|---|---|---|---|
| 1.1 | **Agent 退役向导（Uninstall Wizard）** | 现在的工具只能删单个会话，删不掉「这个 Agent 我不想用了」这件事 | 5 阶段：①**预检**（进程在跑？有活动会话？有 pinned？）→ ②**调用官方卸载器**（`QuietUninstallString`，无静默参数的降级为交互式，由用户点）→ ③**前后快照对比** → ④**残留分级处置** → ⑤**报告 + 可回滚** |
| 1.2 | **残留扫描器（Residue Scanner）** | 取代硬编码的 2 条死提示 | 7 类信号源：注册表卸载项（含 InstallLocation/UninstallString/DisplayIcon）、已知目录命名规律（`@scope-app`、`com.vendor.app`、`.agentname`）、开始菜单 `.lnk` 目标反查、`%TEMP%` 前缀、HKCU/HKLM vendor 键、防火墙规则、计划任务/Run 键。每条残留必须带**证据字符串**（"因为注册表项 X 指向 Y"） |
| 1.3 | **三级处置 + 逐条勾选** | 残留不能一刀切 | `safe`（明确属于该 Agent 且可再生产）/ `review`（需人工判断）/ `never`（用户数据、共享资源、git 仓库）。UI 默认只勾 `safe`，`review` 必须手动展开勾选，`never` 只读展示 |
| 1.4 | **空壳目录识别** | `~/WorkBuddy`、`%APPDATA%/WorkBuddy`、`E:\WorkBuddyStorage` 这类 0 文件残留 | 单独一类：目录存在但递归 0 文件 0 字节 → 安全删，且这类最容易被手工遗漏 |
| 1.5 | **密钥/凭据残留专项** | `~/.workbuddy-key-fallback/connector-keys/*.key` 实测存在 | 识别密钥类文件（`.key`/`.pem`/`credentials*`/`*token*`），**单独高亮**：「此处有密钥材料，卸载后是否一并销毁？」——这既是清理也是安全 |
| 1.6 | **注册表键清理** | 卸载器经常留下 HKCU vendor 键 | `HKCU` 可直接删；`HKLM` 标记需管理员。删前导出 `.reg` 备份到隔离区，走同一套 journal/回滚 |
| 1.7 | **防火墙规则 / 计划任务清理** | `WorkBuddy editor_sdk` 2 条规则实测存在 | 需管理员。先导出规则 XML 再删，可回滚 |
| 1.8 | **快捷方式清理** | 3 个 `.lnk` 实测存在 | 低风险，但要校验 `.lnk` 目标确实已不存在才删 |
| 1.9 | **卸载后验证** | 卸载器报成功 ≠ 真干净 | 复用现有 `verify_absent()` 模式：卸载后重扫，列出**仍然存在**的项，形成闭环报告 |

### 第 2 批 — 真正的空间回收（会话只占 0.9%，这里是 3.9 GB）

| # | 功能 | 解决什么 | 实现要点 |
|---|---|---|---|
| 2.1 | **可再生缓存清理** | `transport-profile` 472 MB、Electron/WebView2 缓存 | 只清**纯缓存目录名**（Cache/GPUCache/Code Cache/ShaderCache/Crashpad/component_crx_cache…）。实测顶层纯缓存仅 0.4 MB，**嵌套缓存 327 MB**——说明必须递归识别，且嵌套的要多一道人工确认 |
| 2.2 | **插件/组件体积排行** | `~/.workbuddy/plugins` 147 MB、`node_modules` 258 MB、`binaries` 483 MB | 做「占用排行」页：按目录列出 Top N，标注「可再生 / 需重新下载 / 配置·勿动」。**不做自动删除**，只做透明化 + 一键清可再生的那类 |
| 2.3 | **日志与旧日志清理** | `~/.workbuddy/logs` 5.8 MB、`%TEMP%/dsh-*` | 按 mtime 清理（如 >7 天），跳过被进程占用的。实测 `dsh-acl-locks` 可能正在使用，必须探测 |
| 2.4 | **重复内容检测** | `~/.dsh/dsh-session-archive` vs `~/.dsh/sessions` 疑似重复；同一会话的附件可能多份 | 按内容哈希（大小 + 前 64 KB 哈希）找重复，先报告后处置 |
| 2.5 | **跨 Agent 同项目聚合** | 一个项目用了 5 个 Agent，散在 5 个地方 | 按 `cwd` 归一化聚合：`E:\proj` 下所有 Agent 的会话/缓存/插件一行展示，支持「整个项目退役」 |
| 2.6 | **磁盘增长趋势** | 现在只有瞬时快照，不知道「什么时候该清」 | 每次扫描把 footprint 追加到 `_data/history.jsonl`，画增长曲线；按增长率预测「N 天后超过阈值」 |

### 第 3 批 — 会话本身的能力补强

| # | 功能 | 解决什么 | 实现要点 |
|---|---|---|---|
| 3.1 | **敏感信息扫描** | 会话正文里可能有 key/token/密码，删之前值得知道 | 复用 `core/search.py` 的原始文本索引，加正则规则（`sk-*`、`ghp_*`、`AKIA*`、私钥头）。**只报告不阻断**，回显时打码 |
| 3.2 | **导出后即删（归档流）** | 「舍不得删但得腾地方」 | 现在 `core/export.py` 能导出 markdown/json。串成一步：「导出 → 校验导出完整性 → 压缩 → 删源」，校验失败则中止 |
| 3.3 | **定时保留策略（dry-run 优先）** | 现在是手动点 | 复用 `core/retention.py` 的 7 条规则 + 评分。默认**只生成待办报告**，不自动删；自动删必须显式开启且限定低分档 |
| 3.4 | **删除前「价值」二次确认** | 现在预览要点进去才看到 | 对 `high` 价值档的会话，删除时强制展示标题 + 轮次 + 用量摘要 |
| 3.5 | **CLI 模式** | GUI 不适合批量/脚本 | `python cli.py scan|sessions|plan|delete|residue|uninstall --json`。复用同一套 core，不重复实现 |
| 3.6 | **操作日志可查询/导出** | `operations.jsonl` 现在只读展示 | 按时间/Agent/结果过滤，导出 CSV 作为审计记录 |

---

## 3. 明确**不做**的（避免范围失控）

| 不做 | 原因 |
|---|---|
| 自动卸载 Agent | 卸载是破坏性且不可逆（卸载器本身没有回滚），必须人工点确认。工具只负责**预检 + 调用 + 验证** |
| 删除安装目录 | 交给官方卸载器。手工删安装目录会留下更多注册表残渣 |
| 跨 Agent 会话迁移/转换 | 格式差异大（zstd JSONL / SQLite / FTS5），收益低、易损坏数据 |
| MCP 接口 | 与「本地安全工具」定位冲突，扩大攻击面 |
| 深度清理 `HKLM\SOFTWARE\Tencent` | 与 QQ/微信共用，删了会影响其他软件 |

---

## 4. 建议的实施顺序

如果要动手，我建议这个顺序——每一步都能独立验证，不会出现「改了一半不能用」：

1. **0.1 + 0.4**（归属模型 + dry-run）— 是 1.x 全批的地基，先做
2. **1.2 + 1.3 + 1.4**（残留扫描 + 三级处置 + 空壳）— 直接解决你问的问题，且**只读**，可以立刻看到效果
3. **1.1 + 1.9**（卸载向导 + 验证）
4. **2.1 + 2.3 + 2.6**（缓存/日志清理 + 趋势）— 真正回收空间
5. **1.5**（密钥专项）— 安全价值高，可提前
6. **0.2**（隔离区保留策略）— 在开始删大目录**之前**必须完成
7. 其余按需

---

## 5. 验收口径（怎么算做对了）

沿用现有测试风格，每个新功能都要有独立自测套件，且遵守既有铁律：

- **删除类测试**在导入 adapter **之前**把 `USERPROFILE`/`APPDATA`/`LOCALAPPDATA` 指向临时沙箱
- **绝不能**碰到真实会话；`selftest_realdb.py` 只读真实库、写副本、逐行比对
- 新增 `selftest_residue.py`：喂入伪造的注册表/目录树，断言「`E:\workbuddyapi-main` 这类 git 仓库被判为 `never`」
- 新增 `selftest_uninstall.py`：用假卸载器（打印参数后退出）验证 5 阶段流程与回滚
- `audit_static.py` 保持不 import `selftest_*.py`
- 所有清理操作在测试后必须留下**零**临时沙箱

---

## 6. 需要你定的三件事

1. **范围**：先做第 1 批（卸载/残留，你原话要的），还是先做第 2 批（空间回收，实测 3.9 GB 的大头）？
2. **注册表**：允许删 `HKCU` 键吗？`HKLM` 需要提权，遇到时是「提示你手动」还是「尝试提权」？
3. **卸载器**：允许工具**调用**官方卸载器吗？（这是唯一不可逆的一步，我个人建议允许调用但强制人工确认，且不代按「下一步」）
