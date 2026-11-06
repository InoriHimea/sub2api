## Context

接入官方main/c5ca149a（Go1.27.3），旧0.2.17/0.2.19补丁仅用于一次性源码迁移，旧验收不替代最新基线验证。仓库/来源身份归upstream.lock.json和FORK.md；API规范入口为docs/usage-hourly.md。

## Decisions

- 延续UsageLogRepository→UsageService→UsageHandler→既有admin usage路由；新增聚合方法，所有受影响的显式实现/测试stub同步，不增加可选接口回退或保留双实现。
- 单次原始usage_logs SELECT提供一致快照，显式UTC date_trunc避免会话时区/DST改变桶边界；查询参数绑定，分组和请求模型沿原有表达式。
- 返回可加总sum/count而非另一套均值；COUNT(duration_ms)排除NULL包含0。费用cost/actual_cost/account_cost保留既有独立语义。
- 输入区间精确、半开，可裁剪边缘小时；PG仅存微秒，SQL起止界限均ceiling到微秒网格，保留原RFC3339界限回显，防止数据库四舍五入漏行。
- 最长31天、最多100000行，LIMIT100001仅用于发现超限，整轮422而非部分成功。游标/扫描/关闭失败整轮失败；空结果保持[]不补0。
- 最新上游已增加受限管理员key权限目录；显式新全站usage.hourly.read只允许GET /usage/hourly，不将其并入usage.read或dashboard.read，防止既有key静默扩权。该源代码适配不授予任何线上身份。

## Verification and risks

永久测试使用真实admin JWT中间件与实际路由注册、HTTP server和repository；显式合成loopback *_test PG临时表覆盖时区/偏移/半开及亚微秒界限、NULL/0、组与模型、费用和溢出。普通轮缺PG时只Skip，显式PG验收必须pass且无Skip。权限目录行为测试证明新权限和明细权限相互隔离。

整年消费者可以组合多个闭合桶/分段请求；不能把部分桶覆盖完整桶，也不能用requests替代有效耗时count。原始日志保留期可能限制回填历史，不将上游无记录自动解释为零；消费者展示/存储策略归下游项目，不在本fork任务里伪造数据。

## Release boundary

本轮不部署/发布镜像、不读取业务秘密、不修改线上key策略；源代码和任务迁移完成后仍须单独完成现役差异/回退、Test发布、受控新GET消费和真实小时对账。
