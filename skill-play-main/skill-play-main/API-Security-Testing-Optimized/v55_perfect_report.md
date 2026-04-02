# 深度 API 渗透测试报告 v5.5 (完美版)

## 执行摘要
- **测试目标**: http://58.215.18.57:91
- **测试时间**: 2026-04-01 07:43:54
- **测试工具**: Deep API Tester v5.5

## 发现统计
| 类型 | 数量 |
|------|------|
| JS 文件 | 15 |
| API 端点 | 164 |
| 漏洞数量 | 9 |

## JS 文件
- `http://58.215.18.57:91/jquery.js`
- `http://58.215.18.57:91/config.js`
- `http://58.215.18.57:91/static/js/runtime.6189983e.js`
- `http://58.215.18.57:91/static/js/chunk-echarts.d03bf505.js`
- `http://58.215.18.57:91/static/js/chunk-elementUI.2395d8d8.js`
- `http://58.215.18.57:91/static/js/chunk-vue.6c5afe5f.js`
- `http://58.215.18.57:91/static/js/chunk-zrender-lib.663e0021.js`
- `http://58.215.18.57:91/static/js/chunk-small-wei.27227356.js`
- `http://58.215.18.57:91/static/js/chunk-libs.c18fc3ed.js`
- `http://58.215.18.57:91/static/js/6707.47b66700.js`
- `http://58.215.18.57:91/static/js/index.0d365cba.js`
- `http://58.215.18.57:91/static/js/6250.39db9c37.js`
- `http://58.215.18.57:91/static/js/7703.7aa21fa0.js`
- `http://58.215.18.57:91/static/js/8798.13c5f408.js`
- `http://58.215.18.57:91/static/js/2392.7d0980fd.js`

## API 端点 (164 个)
- `GET http://58.215.18.57:91/dist`
- `GET http://172.16.77.188:8083/basic-platform/licence/authentication`
- `GET http://58.215.18.57:91/a/b`
- `GET http://58.215.18.57:91/a/i`
- `GET http://58.215.18.57:91/group`
- `GET http://58.215.18.57:91/named`
- `GET http://58.215.18.57:91/api/v1/map`
- `GET http://58.215.18.57:91/script`
- `GET http://58.215.18.57:91/redirect`
- `GET http://58.215.18.57:91/flowable/api/v1/process/read/xml`
- `GET http://58.215.18.57:91/oa/task/flow/record`
- `GET http://58.215.18.57:91/flowable/api/v1/process/complete`
- `GET http://58.215.18.57:91/oa/detail/common/process/instance`
- `GET http://58.215.18.57:91/oa/detail/common/business`
- `GET http://58.215.18.57:91/oa/approval/common/start`
- `GET http://58.215.18.57:91/oa/approval/common/save/draft`
- `GET http://58.215.18.57:91/oa/attachment/query`
- `GET http://58.215.18.57:91/oa/attachment/upload`
- `GET http://58.215.18.57:91/oa/attachment`
- `GET http://58.215.18.57:91/oa/system/users`
- `GET http://58.215.18.57:91/oa/system/depts`
- `GET http://58.215.18.57:91/oa/task/node/cat`
- `GET http://58.215.18.57:91/oa/leave/list/date`
- `GET http://58.215.18.57:91/report/bigScreen/viewer`
- `GET http://58.215.18.57:91/user/profile`
- `GET http://58.215.18.57:91/file/upload`
- `GET http://58.215.18.57:91/file/file-minio/object/startUpload`
- `GET http://58.215.18.57:91/file/file-minio/object/merge`
- `GET http://58.215.18.57:91/report/gaeaDict/select`
- `GET http://58.215.18.57:91/report/file/upload`
- `GET http://58.215.18.57:91/resource/info/list`
- `GET http://58.215.18.57:91/resource/info/manageList`
- `GET http://58.215.18.57:91/resource/info/listByAlgo`
- `GET http://58.215.18.57:91/resource/info/ipScan`
- `GET http://58.215.18.57:91/resource/info/confirm`
- `GET http://58.215.18.57:91/resource/info`
- `GET http://58.215.18.57:91/resource/info/logicDelete`
- `GET http://58.215.18.57:91/resource/info/recentSearch`
- `GET http://58.215.18.57:91/resource/info/deviceSummary`
- `GET http://58.215.18.57:91/resource/info/stopIpScan`
- `GET http://58.215.18.57:91/resource/info/import/detail`
- `GET http://58.215.18.57:91/resource/info/update`
- `GET http://58.215.18.57:91/resource/info/updateBatch`
- `GET http://58.215.18.57:91/system/record/applicantList`
- `GET http://58.215.18.57:91/system/record/approverList`
- `GET http://58.215.18.57:91/system/record/appList`
- `GET http://58.215.18.57:91/system/desktop/application/desktop`
- `GET http://58.215.18.57:91/system/desktop/application`
- `GET http://58.215.18.57:91/system/app/detail`
- `GET http://58.215.18.57:91/system/record`
- `GET http://58.215.18.57:91/system/record/followUp`
- `GET http://58.215.18.57:91/system/record/withDraw`
- `GET http://58.215.18.57:91/system/record/review`
- `GET http://58.215.18.57:91/system/record/reviewCount`
- `GET http://58.215.18.57:91/msgcenter/template/list`
- `GET http://58.215.18.57:91/msgcenter/template`
- `GET http://58.215.18.57:91/msgcenter/content/list`
- `GET http://58.215.18.57:91/msgcenter/content`
- `GET http://58.215.18.57:91/msgcenter/api/push/selectByUserId`
- `GET http://58.215.18.57:91/msgcenter/api/push/selectByTableName`
- `GET http://58.215.18.57:91/lib/theme-chalk/index.css`
- `GET http://58.215.18.57:91/system/dict/data/list`
- `GET http://58.215.18.57:91/system/dict/data`
- `GET http://58.215.18.57:91/system/dict/data/type`
- `GET http://58.215.18.57:91/report/gaeaDict/all`
- `GET http://58.215.18.57:91/report/bigScreen/designer`
- `GET http://58.215.18.57:91/report/excelreport/viewer`
- `GET http://58.215.18.57:91/report/excelreport/designer`
- `GET http://58.215.18.57:91/redirect/:path(.*)`
- `GET http://58.215.18.57:91/behaviorTaskManage/behaviorTaskReal`
- `GET http://58.215.18.57:91/behaviorTaskManage/behaviorSubTaskReal`
- `GET http://58.215.18.57:91/eventAlarm/eventAlarmVideoGroup`
- `GET http://58.215.18.57:91/eventAlarm/rEventAlarmVideoGroup`
- `GET http://58.215.18.57:91/eventAlarm/event_alarm_conf`
- `GET http://58.215.18.57:91/report/FormStatistics`
- `GET http://58.215.18.57:91/report/reportStatistical`
- `GET http://58.215.18.57:91/subscribe/HikvisionConfig`
- `GET http://58.215.18.57:91/report/dsf`
- `GET http://58.215.18.57:91/report/errorlog`
- `GET http://58.215.18.57:91/form/detail/:cFormKey`
- `GET http://58.215.18.57:91/system/user-auth`
- `GET http://58.215.18.57:91/system/user`
- `GET http://58.215.18.57:91/system/role-auth`
- `GET http://58.215.18.57:91/system/role`
- `GET http://58.215.18.57:91/system/dict-data`
- `GET http://58.215.18.57:91/system/dict`
- `GET http://58.215.18.57:91/system/tag-data`
- `GET http://58.215.18.57:91/system/tag`
- `GET http://58.215.18.57:91/monitor/job-log`
- `GET http://58.215.18.57:91/monitor/job`
- `GET http://58.215.18.57:91/resReport/relateDevice`
- `GET http://58.215.18.57:91/resReport/chart`
- `GET http://58.215.18.57:91/vision/job/log`
- `GET http://58.215.18.57:91/vision/job/index`
- `GET http://58.215.18.57:91/system/menu/getRouters`
- `GET http://58.215.18.57:91/system/menu/getRoutersByAppId`
- `GET http://58.215.18.57:91/system/config/list`
- `GET http://58.215.18.57:91/system/config`
- `GET http://58.215.18.57:91/system/config/configKey`
- `GET http://58.215.18.57:91/system/config/refreshCache`
- `GET http://58.215.18.57:91/system/app/list`
- `GET http://58.215.18.57:91/system/app`
- `GET http://58.215.18.57:91/system/app/getAllApp`
- `GET http://58.215.18.57:91/system/app/restartApp`
- `GET http://58.215.18.57:91/file/file-minio/object/upload`
- `GET http://58.215.18.57:91/file/file-minio/object/getImg`
- `GET http://58.215.18.57:91/report/reportDashboard`
- `GET http://58.215.18.57:91/report/dataSet/queryAllDataSet`
- `GET http://58.215.18.57:91/report/dataSet/detailBysetId`
- `GET http://58.215.18.57:91/report/reportDashboard/getData`
- `GET http://58.215.18.57:91/report/reportDashboard/export`
- `GET http://58.215.18.57:91/websocket`
- `GET http://58.215.18.57:91/system/desktop/getInfo`
- `GET http://58.215.18.57:91/system/desktop`
- `GET http://58.215.18.57:91/system/desktop/getDeskTopRouters`
- `GET http://58.215.18.57:91/system/desktopGroup/getAllDesktopGroups`
- `GET http://58.215.18.57:91/system/desktopGroup/getDesktopGroupByName`
- `GET http://58.215.18.57:91/auth/login`
- `GET http://58.215.18.57:91/auth/external/login`
- `GET http://58.215.18.57:91/auth/refresh`
- `GET http://58.215.18.57:91/system/user/getInfo`
- `GET http://58.215.18.57:91/auth/logout`
- `GET http://58.215.18.57:91/system/app/getAppByAppId`
- `GET http://58.215.18.57:91/system/externalSystem/getAllExternalSystem`
- `GET http://58.215.18.57:91/system/user/sendCode/login`
- `GET http://58.215.18.57:91/system/user/sendCode/reset`
- `GET http://58.215.18.57:91/system/user/resetPwdByCode`
- `GET http://58.215.18.57:91/auth/sms/login`
- `GET http://58.215.18.57:91/login`
- `GET http://58.215.18.57:91/reset`
- `GET http://58.215.18.57:91/bind`
- `GET http://58.215.18.57:91/register`
- `GET http://58.215.18.57:91/workbench`
- `GET http://58.215.18.57:91/changepwd`
- `GET http://58.215.18.57:91/externalLogin`
- `GET http://58.215.18.57:91/bridge`
- `GET http://58.215.18.57:91/apply`
- `GET http://58.215.18.57:91/audit`
- `GET http://58.215.18.57:91/index`
- `GET http://58.215.18.57:91/playmode`
- `GET http://58.215.18.57:91/map`
- `GET http://58.215.18.57:91/visonReport`
- `GET http://58.215.18.57:91/gismap`
- `GET http://58.215.18.57:91/contentOffice`
- `GET http://58.215.18.57:91/user`
- `GET http://58.215.18.57:91/flowable`
- `GET http://58.215.18.57:91/apps`
- `GET http://58.215.18.57:91/cabinet`
- `GET http://58.215.18.57:91/video`
- `GET http://58.215.18.57:91/area`
- `GET http://58.215.18.57:91/server`
- `GET http://58.215.18.57:91/unifiedMonitoring`
- `GET http://58.215.18.57:91/lampstand`
- `GET http://58.215.18.57:91/home`
- `GET http://58.215.18.57:91/behaviorTaskReal`
- `GET http://58.215.18.57:91/eventReport`
- `GET http://58.215.18.57:91/operationLog`
- `GET http://58.215.18.57:91/test`
- `GET http://58.215.18.57:91/code`
- `GET http://58.215.18.57:91/system/configuration/list`
- `GET http://58.215.18.57:91/system/configuration/edit`
- `GET http://58.215.18.57:91/system/api/user/register/dept`
- `GET http://58.215.18.57:91/system/api/user/register/code`
- `GET http://58.215.18.57:91/system/api/user/register`

## 漏洞详情
### Unauthorized Access
- **严重程度**: HIGH
- **端点**: http://58.215.18.57:91/system/config/list
- **证据**: Status: 200

### Unauthorized Access
- **严重程度**: HIGH
- **端点**: http://58.215.18.57:91/system/config
- **证据**: Status: 200

### Unauthorized Access
- **严重程度**: HIGH
- **端点**: http://58.215.18.57:91/system/config/configKey
- **证据**: Status: 200

### Unauthorized Access
- **严重程度**: HIGH
- **端点**: http://58.215.18.57:91/system/config/refreshCache
- **证据**: Status: 200

### Unauthorized Access
- **严重程度**: HIGH
- **端点**: http://58.215.18.57:91/system/configuration/list
- **证据**: Status: 200

### Unauthorized Access
- **严重程度**: HIGH
- **端点**: http://58.215.18.57:91/system/configuration/edit
- **证据**: Status: 200

### Unauthorized Access
- **严重程度**: HIGH
- **端点**: http://58.215.18.57:91/system/api/user/register/dept
- **证据**: Status: 200

### Unauthorized Access
- **严重程度**: HIGH
- **端点**: http://58.215.18.57:91/system/api/user/register/code
- **证据**: Status: 200

### Unauthorized Access
- **严重程度**: HIGH
- **端点**: http://58.215.18.57:91/system/api/user/register
- **证据**: Status: 200

