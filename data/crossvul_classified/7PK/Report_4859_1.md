# CrossVul Fix Pair: 7PK in python
**Pair ID:** 4859_1
**Vulnerability Class:** 7PK
**CWE:** CWE-254
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4859_1`)

## Vulnerability Information & PoC

## Description
7PK - Security Features

## Vulnerable Code
```python
Lines 87-127 of the vulnerable file.

            if len(fields) > 2:
                hosts[fields[0].strip()] = (  # ip
                    int(fields[1].strip()),  # n attemps
                    int(fields[2].strip())   # last attempts
                    )
        portalocker.unlock(f)
        f.close()
    return hosts


def write_hosts_deny(denied_hosts):
    f = open(deny_file, 'w')
    portalocker.lock(f, portalocker.LOCK_EX)
    for key, val in denied_hosts.items():
        if time.time() - val[1] < expiration_failed_logins:
            line = '%s %s %s\n' % (key, val[0], val[1])
            f.write(line)
    portalocker.unlock(f)
    f.close()


def login_record(success=True):
    denied_hosts = read_hosts_deny()
    val = (0, 0)
    if success and request.client in denied_hosts:
        del denied_hosts[request.client]
    elif not success and not request.is_local:
        val = denied_hosts.get(request.client, (0, 0))
        if time.time() - val[1] < expiration_failed_logins \
            and val[0] >= allowed_number_of_attempts:
            return val[0]  # locked out
        time.sleep(2 ** val[0])
        val = (val[0] + 1, int(time.time()))
        denied_hosts[request.client] = val
    write_hosts_deny(denied_hosts)
    return val[0]


# ###########################################################
# ## session expiration
# ###########################################################
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -104,13 +104,12 @@
     portalocker.unlock(f)
     f.close()
 
-
 def login_record(success=True):
     denied_hosts = read_hosts_deny()
     val = (0, 0)
     if success and request.client in denied_hosts:
         del denied_hosts[request.client]
-    elif not success and not request.is_local:
+    elif not success:
         val = denied_hosts.get(request.client, (0, 0))
         if time.time() - val[1] < expiration_failed_logins \
             and val[0] >= allowed_number_of_attempts:
@@ -119,6 +118,11 @@
         val = (val[0] + 1, int(time.time()))
         denied_hosts[request.client] = val
     write_hosts_deny(denied_hosts)
+    return val[0]
+
+def failed_login_count():
+    denied_hosts = read_hosts_deny()
+    val = denied_hosts.get(request.client, (0, 0))
     return val[0]
 
 
```
