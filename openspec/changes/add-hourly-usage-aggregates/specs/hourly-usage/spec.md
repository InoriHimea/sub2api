## Purpose

为长期维护fork提供不含请求/用户明细的UTC小时×组×请求模型用量聚合，使耗时可以跨桶正确组合。

## ADDED Requirements

### Requirement: 显式只读聚合授权
系统 MUST 在现有管理员认证下提供GET /api/v1/admin/usage/hourly；受限key MUST 显式具有usage.hourly.read，MUST NOT 因已有usage.read/dashboard.read自动获得新接口，新权限 MUST NOT 授予明细或写入。

#### Scenario: 最小权限不扩大
- **WHEN** 受限key只有usage.hourly.read
- **THEN** GET小时聚合可被授权，但GET用量明细/用户资料和POST操作 MUST 被拒绝。

#### Scenario: 既有key不静默扩权
- **WHEN** key仅有旧usage.read或dashboard.read
- **THEN** 新小时聚合 MUST 不被这些权限单独授予。

### Requirement: 精确半开区间与UTC小时
系统 MUST 接受带时区RFC3339 start_time/end_time、start<end且最长31天，按[start,end)筛选，UTC小时分桶，支持部分边缘小时并保留原精度归一UTC界限。SQL比较 MUST 不因PG微秒精度舍入改变存储点的包含关系。

#### Scenario: 纳秒界限包围一个微秒存储点
- **WHEN** 请求界限为00:29:59.9999999Z至00:30:00.0000004Z
- **THEN** 存储的00:30:00Z记录 MUST 被包含且准确计数，恰好在原结束界限的记录 MUST 被排除。

### Requirement: 可加总且不泄露明细的统计
每行 MUST 以UTC小时、nullable group_id和请求模型为维度，返回请求/tokens、独立三类费用以及duration_sum_ms/count；count MUST 排除NULL且包含0，MUST NOT 返回用户/key/account明细标识。

#### Scenario: NULL与0ms混合
- **WHEN** 同桶耗时为100、NULL、0
- **THEN** duration_sum_ms MUST 为100、duration_count MUST 为2；组合均值为50ms而不是按三个请求求均值。

### Requirement: 稀疏结果与完整失败
系统 MUST 以单SELECT快照读取，空结果为[]且不补0；超过100000行 MUST 明确422，查询/扫描/游标/关闭失败 MUST 不返回部分成功。

#### Scenario: 超限或中途数据库失败
- **WHEN** 结果超限，或已读部分行后发生数据库错误
- **THEN** 系统 MUST 返回明确失败，MUST NOT 把部分数据当完整结果。
