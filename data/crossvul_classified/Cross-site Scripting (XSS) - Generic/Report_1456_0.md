# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 1456_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1456_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 186-226 of the vulnerable file.

            and p.source_rpm_id = ps.source_rpm_id
            and ((p.org_id is null and ps.org_id is null)
                or p.org_id = ps.org_id)
    """
    h = rhnSQL.prepare(statement)
    h.execute(name=pkgFilename, channel=channel, server_id=server_id)
    return h.fetchone_dict()


def get_info_for_package(pkg, channel_id, org_id):
    log_debug(3, pkg)
    pkg = map(str, pkg)
    params = {'name': pkg[0],
              'ver': pkg[1],
              'rel': pkg[2],
              'epoch': pkg[3],
              'arch': pkg[4],
              'channel_id': channel_id,
              'org_id': org_id}
    # yum repo has epoch="0" not only when epoch is "0" but also if it's NULL
    if pkg[3] == '0' or pkg[3] == '':
        epochStatement = "(epoch is null or epoch = :epoch)"
    else:
        epochStatement = "epoch = :epoch"
    if params['org_id']:
        orgStatement = "org_id = :org_id"
    else:
        orgStatement = "org_id is null"

    statement = """
    select p.path, cp.channel_id,
           cv.checksum_type, cv.checksum
      from rhnPackage p
      join rhnPackageName pn
        on p.name_id = pn.id
      join rhnPackageEVR pe
        on p.evr_id = pe.id
      join rhnPackageArch pa
        on p.package_arch_id = pa.id
      left join rhnChannelPackage cp
        on p.id = cp.package_id
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -203,7 +203,7 @@
               'channel_id': channel_id,
               'org_id': org_id}
     # yum repo has epoch="0" not only when epoch is "0" but also if it's NULL
-    if pkg[3] == '0' or pkg[3] == '':
+    if pkg[3] == '0' or pkg[3] == '' or pkg[3]==None:
         epochStatement = "(epoch is null or epoch = :epoch)"
     else:
         epochStatement = "epoch = :epoch"
```
