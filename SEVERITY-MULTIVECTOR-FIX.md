# 多向量评分聚合失真修复交付文档

## 1. 根因

评分整链为：OSV 记录 → `severity.CalculateOverallScore`（单记录多向量聚合）→
`grouper.calculateMaxSeverities`（组级聚合，写入 `GroupInfo.MaxSeverity`）→
`output.processVulnGroups`（`SeverityScore` / `SeverityRating`）→ 终端表格评分列与
`SeverityCount` 汇总（Critical/High/Medium/Low/Unknown）。

缺陷落在第一环：`CalculateOverallScore` 对每个向量调用 `CalculateScore` 后**遇到第一个
错误立即 `return -1, UNKNOWN, err`**，直接丢弃此前已累积的最高分。因此一条记录只要携带
任意一条畸形向量（例如 `A:X` 这类非法度量值），整条记录的组级分数就退化为 `-1`：

- `grouper` 把 `-1` 与初值取 max，结果为 `-1` → `MaxSeverity` 落成空串；
- `output` 对空串调用 `CalculateRating` 失败 → 评分列显示 `N/A`（空白），评级 `UNKNOWN`；
- 汇总行该记录全部计入 `Unknown`，严重级计数全零。

`grouper/build.go:25` 与 `internal/output/sarif.go:317` 都用 `_` 丢弃该错误，所以错误既
没有被上游感知，也无法触发流水线唯一卡点（退出码）之外的任何降级校验。这就是"肉眼可见
8.8、报告却空白"的原因。

修复前的实测复现（同一条记录，合法向量 `CVSS:3.1/.../A:H` = 8.8，畸形向量 `.../A:X`）：

```
single valid       -> 8.8 HIGH err=<nil>
single malformed   -> -1.0 UNKNOWN err=invalid metric value
overall mixed      -> -1.0 UNKNOWN err=invalid metric value   ← 合法分数被整条丢弃
overall bad-only   -> -1.0 UNKNOWN err=invalid metric value
group mixed        -> MaxSeverity=""                          ← 报告评分列因此空白
group good-only    -> MaxSeverity="8.8"
```

## 2. 修复选型与错误处置口径（理由）

改动点：`internal/utility/severity/severity.go` 的 `CalculateOverallScore`。

选型：**逐向量容错 + 末尾按"是否拿到可用分数"决定是否报错**。

- 单条 `CalculateScore` 返回错误时，仅跳过该条目并收集错误，继续参与后续条目的取最大值；
- 合法向量照常按 `score > maxScore` 取最大，**聚合语义（取最大分数及其对应评级）完全不变**；
- 循环结束后：
  - 若至少拿到了一个可用分数（`maxScore >= 0`），返回该分数与评级，`error` 为 `nil`；
  - 若一条可用分数都没有且存在解析错误，返回既有未知口径 `(-1, "UNKNOWN")` 并
    `errors.Join` 全部解析错误——**"仅畸形向量"的对外行为与修复前逐字一致**；
  - 若从未出现错误（如空切片、仅有 `UNSPECIFIED`/Ubuntu 优先级条目的记录），与修复前
    一样返回 `(-1, "UNKNOWN", nil)`。

理由：

1. **降级口径**：一条记录里混入畸形向量的本质是数据质量问题，不是聚合失败。聚合只要
   还有可解析向量可用，就应产出可用分数，避免单点脏数据放大为整条记录（进而整份报告）
   的评分与计数失真。
2. **保留既有未知口径**：仅在"全畸形"时输出未知，既满足题面对既有行为的保持要求，也让
   "无可用评分"这一语义仍然可被下游区分（`MaxSeverity == ""` → 评分列 `N/A` → 计入
   `Unknown`），汇总计数口径不回归。
3. **错误处置**：选择"部分失败不报错、全部失败才报错"而非"一律吞掉错误"或"一律上抛"。
   前者保留可观测性——完全无法评分的记录仍能把解析错误暴露给日志/调试调用方，且该返回值
   与修复前完全一致，不会让既有调用方行为变化；后者会把脏数据放大为整条记录失效，正是
   本次缺陷。`errors.Join` 而非只返回首个错误，是为了在完全失败时一次看清所有畸形向量。
4. 未改动 `CalculateScore` 单向量语义、未改动 `grouper` / `output` 的聚合与计数代码，因此
   汇总计数口径、终端/快照呈现均无回归面；`internal/output/sarif.go` 同样调用
   `CalculateOverallScore`，也顺带获得"脏向量不吞合法分数"的修复。

## 3. 逐文件登记与题面要求映射

| 文件 | 改动 | 对应题面要求 |
| --- | --- | --- |
| `internal/utility/severity/severity.go` | `CalculateOverallScore` 改为逐向量容错聚合：畸形向量跳过并收集错误，合法向量仍取最大值；仅当无任何可用分数时返回既有的 `(-1, "UNKNOWN")` 并用 `errors.Join` 回报解析错误；新增函数注释说明容错与错误口径 | 定位根因并修复；混合向量给出可解析向量的可用分数；畸形向量不得让同记录合法向量分数一并丢失；仅畸形向量时保持既有未知口径；聚合语义与汇总计数口径不回归；修复选型与错误处置口径（理由见 §2） |
| `internal/utility/severity/severity_test.go` | 新增代码内夹具 `severityFixtureVectors` / `severityFixtureRecords`（`OSV-MIXED` 混合、`OSV-MALFORMED` 仅畸形，零外部依赖）与表驱动用例 `TestSeverity_CalculateOverallScore`；用例在断言 `CalculateOverallScore` 返回值的同时，用 `grouper.Build` 取得该记录的组级 `MaxSeverity` 一并断言 | 构造输入取代码内夹具自建的两份漏洞记录；零外部依赖可复现；并入严重度评分既有单元测试文件、沿用其表驱动 + `t.Parallel` + 十分位取整比较的既有框架、不另建测试文件；混合向量给分与全畸形保持未知两类断言用例各至少一条；读数口径取分组聚合预计算后的组级严重度分数 |

未改动文件（有意收窄改动面）：`internal/grouper/build.go`（组级聚合逻辑本身正确，
`severity.CalculateOverallScore` 修好后组级读数自动恢复）、`internal/output/*`（呈现与汇总
计数逻辑本身正确）、全部快照文件。改动面仅落在评分与分组聚合实现及其测试。
`internal/grouper/build_test.go` 未改动：其既有断言（含 `MaxSeverity: "8.8"`）在修复后仍成立。

## 4. 验收命令与实测读数

### 4.1 验收命令

```bash
go test -count=1 ./internal/utility/severity/... ./internal/grouper/... ./internal/output/...
```

实测输出（Go 1.27.4，Windows amd64）：

```
ok  	github.com/google/osv-scanner/v2/internal/utility/severity	0.777s
ok  	github.com/google/osv-scanner/v2/internal/grouper	2.313s
ok  	github.com/google/osv-scanner/v2/internal/output	0.411s
?   	github.com/google/osv-scanner/v2/internal/output/sbom	[no test files]
```

退出码 `0`，三个目标包全部 `ok`，无 `FAIL`；以 `-v` 运行统计到 1118 条 `--- PASS`
断言行（含子用例）。快照文件零改动（`git status` 仅显示 §3 的两个文件），既有测试全部保持通过。

### 4.2 构造输入下的读数

构造输入即 §3 所列代码内夹具，复现命令（零外部依赖，快照测试环境内可跑）：

```bash
go test -count=1 -v -run TestSeverity_CalculateOverallScore ./internal/utility/severity/
```

| 构造记录 | 携带向量 | 组级严重度分数（`GroupInfo.MaxSeverity`） | 读数含义 |
| --- | --- | --- | --- |
| `OSV-MIXED` | 合法 `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` + 畸形 `.../A:X` | `"8.8"` | 等于组内可解析向量的单条分数（8.8，评级 `HIGH`） |
| `OSV-MALFORMED` | 仅畸形 `.../A:X` | `""`（未知口径） | 与修复前一致：评分列 `N/A`、评级 `UNKNOWN`、计入 `Unknown` |

配套观察（用同一夹具经 `grouper.Build` → `output.BuildResults` 测得，仅作旁证，非题面读数口径）：
`OSV-MIXED` 评级 `HIGH`，汇总 `High=1 / Unknown=0`；`OSV-MALFORMED` 评级 `UNKNOWN`，
汇总 `High=0 / Unknown=1`——即在分组聚合预计算修复后，汇总严重级计数同步恢复，
既有未知口径保持不变。

用例通过情况：

```
--- PASS: TestSeverity_CalculateOverallScore
    --- PASS: .../no_severities
    --- PASS: .../only_a_malformed_vector                      ← 全畸形保持未知（含组级 "" 断言）
    --- PASS: .../valid_vector_mixed_with_a_malformed_vector   ← 混合向量给 8.8（含组级 "8.8" 断言）
    --- PASS: .../malformed_vector_before_a_valid_vector       ← 顺序无关性
```

`internal/grouper/TestBuild` 全部 14 个子用例（含 `one_vulnerability_with_a_severity` 的
`MaxSeverity: "8.8"` 与 `ubuntu_package_with_unimportant_vulnerabilities` 的 `"8.1"`）
保持通过。
