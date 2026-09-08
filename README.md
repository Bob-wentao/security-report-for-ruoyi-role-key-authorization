# RuoYi 4.8.3 `roleKey` privilege escalation — VulDB submission package

Standalone advisory for comma-injection into RuoYi `roleKey`, which mints the Shiro `admin` role for an ordinary authenticated user.

- Product: [RuoYi](https://github.com/yangzongzhuan/RuoYi)
- Tested commit: `7995a83e04e1a88aaea5a8a7c50570dffcb145e0` (version `4.8.3`)
- English advisory: [security-report-ruoyi-4.8.3-role-key-authorization.md](./security-report-ruoyi-4.8.3-role-key-authorization.md)
- Chinese original: [REPORT.md](./REPORT.md)
- VulDB form copy-paste: [vuldb-submission.md](./vuldb-submission.md)
- Local PoC: [ruoyi-role-key-poc.sh](./ruoyi-role-key-poc.sh)

Use the English advisory as the VulDB/CVE source. Proven impact is unauthorized `CREATE TABLE` after crossing `@RequiresRoles("admin")`, not wildcard `*:*:*` permissions, arbitrary SQL, or RCE.
