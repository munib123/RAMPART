# CrossVul Fix Pair: Reachable Assertion in python
**Pair ID:** 487_2
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `487_2`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```python
Lines 1-41 of the vulnerable file.

from k5test import *

realm = K5Realm(create_host=False, get_creds=False)
usercache = 'FILE:' + os.path.join(realm.testdir, 'usercache')
storagecache = 'FILE:' + os.path.join(realm.testdir, 'save')

# Create two service principals with keys in the default keytab.
service1 = 'service/1@%s' % realm.realm
realm.addprinc(service1)
realm.extract_keytab(service1, realm.keytab)
service2 = 'service/2@%s' % realm.realm
realm.addprinc(service2)
realm.extract_keytab(service2, realm.keytab)

puser = 'p:' + realm.user_princ
pservice1 = 'p:' + service1
pservice2 = 'p:' + service2

# Get forwardable creds for service1 in the default cache.
realm.kinit(service1, None, ['-f', '-k'])

# Try krb5 -> S4U2Proxy with forwardable user creds.  This should fail
# at the S4U2Proxy step since the DB2 back end currently has no
# support for allowing it.
realm.kinit(realm.user_princ, password('user'), ['-f', '-c', usercache])
output = realm.run(['./t_s4u2proxy_krb5', usercache, storagecache, '-',
                    pservice1, pservice2], expected_code=1)
if ('auth1: ' + realm.user_princ not in output or
    'NOT_ALLOWED_TO_DELEGATE' not in output):
    fail('krb5 -> s4u2proxy')

# Again with SPNEGO.
output = realm.run(['./t_s4u2proxy_krb5', '--spnego', usercache, storagecache,
                    '-', pservice1, pservice2],
                   expected_code=1)
if ('auth1: ' + realm.user_princ not in output or
    'NOT_ALLOWED_TO_DELEGATE' not in output):
    fail('krb5 -> s4u2proxy (SPNEGO)')

# Try krb5 -> S4U2Proxy without forwardable user creds.  This should
# result in no delegated credential being created by
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,6 +18,14 @@
 
 # Get forwardable creds for service1 in the default cache.
 realm.kinit(service1, None, ['-f', '-k'])
+
+# Try S4U2Self for user with a restricted password.
+realm.run([kadminl, 'modprinc', '+needchange', realm.user_princ])
+realm.run(['./t_s4u', 'e:user', '-'])
+realm.run([kadminl, 'modprinc', '-needchange',
+          '-pwexpire', '1/1/2000', realm.user_princ])
+realm.run(['./t_s4u', 'e:user', '-'])
+realm.run([kadminl, 'modprinc', '-pwexpire', 'never', realm.user_princ])
 
 # Try krb5 -> S4U2Proxy with forwardable user creds.  This should fail
 # at the S4U2Proxy step since the DB2 back end currently has no
```
