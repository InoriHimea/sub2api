## 1. 最新上游与源码归属

- [x] 1.1 完整clone官方main，固定c5ca149a3d856d92fa0b61bea276338be718c5db，核对非浅历史、Go1.27.3及v0.2.19之后49个提交。
- [x] 1.2 独立私有Bitbucket GWAI/Sub2API仓库创建，origin/upstream及upstream-main锚点分支建立；如实标识跨平台fork而非平台原生origin关联。
- [x] 1.3 小时聚合类型、repository/service/handler/真实路由和永久回归直接迁入backend，必要接口调用方/测试stub同步；不在构建时打patch。

## 2. 最新权限与数据边界

- [x] 2.1 新增显式usage.hourly.read全站只读权限；不自动继承usage.read/dashboard.read，不授权用户明细/POST，不改线上key。
- [x] 2.2 保持UTC半开区间、31天上限、100000行显式拒绝、nullable组和请求模型、三类费用、NULL/0耗时sum/count及SQL微秒网格边界语义。
- [x] 2.3 添加权限隔离行为回归；现有JWT管理员/普通用户认证及真实PG边界回归保留，不以放宽权限令测试通过。

## 3. 最新基线验收与迁移收口

- [x] 3.1 Go1.27.3聚焦单元7项事件、已有权限回归3项事件、相关包构建通过；普通轮门控PG Skip1明确保留。
- [x] 3.2 显式owned loopback *_test合成PG实际HTTP→认证→handler→service→repository测试1pass/0skip。
- [x] 3.3 独立实际TCP HTTP烟测通过；maintenance/verification/仅发布脱敏摘要，原始日志私有保留；合成DB停止且数据和临时脚手架已清理。
- [x] 3.4 服务端实现待办已归本fork，下游只留消费者指针；旧小时聚合patch/lock/helper入口退出，原始输入/日志及运维历史私有保存。
- [x] 3.5 本方源码/任务提交15004bb0已推送并回读；native parent/source、官方祖先和upstream-main锚点已核对，下游绑定该不可变源码commit，迁移完成记录归TODO-m.md。

## 4. 单独发布门禁（本轮不执行）

- [ ] 4.1 核对现役真实commit/已有bug差异及回退材料后，单独批准Test发布和独立制品来源。
- [ ] 4.2 新只读GET的真实消费者权限及小时对账另行验收，采集/存储/UI父目标由下游项目负责。
