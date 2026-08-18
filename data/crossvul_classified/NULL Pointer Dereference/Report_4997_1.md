# CrossVul Fix Pair: NULL Pointer Dereference in python
**Pair ID:** 4997_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4997_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```python
Lines 75-115 of the vulnerable file.

# Test anonymous kadmin.
f = open(os.path.join(realm.testdir, 'acl'), 'a')
f.write('WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS a *')
f.close()
realm.start_kadmind()
realm.run([kadmin, '-n', 'addprinc', '-pw', 'test', 'testadd'])
out = realm.run([kadmin, '-n', 'getprinc', 'testadd'], expected_code=1)
if "Operation requires ``get'' privilege" not in out:
    fail('Anonymous kadmin has too much privilege')
realm.stop_kadmind()

# Test with anonymous restricted; FAST should work but kvno should fail.
r_env = realm.special_env('restrict', True, kdc_conf=restrictive_kdc_conf)
realm.stop_kdc()
realm.start_kdc(env=r_env)
realm.kinit('@%s' % realm.realm, flags=['-n'])
realm.kinit('@%s' % realm.realm, flags=['-n', '-T', realm.ccache])
out = realm.run([kvno, realm.host_princ], expected_code=1)
if 'KDC policy rejects request' not in out:
    fail('Wrong error for restricted anonymous PKINIT')

# Go back to a normal KDC and disable anonymous PKINIT.
realm.stop_kdc()
realm.start_kdc()
realm.run([kadminl, 'delprinc', 'WELLKNOWN/ANONYMOUS'])

# Run the basic test - PKINIT with FILE: identity, with no password on the key.
realm.run(['./responder', '-x', 'pkinit=',
           '-X', 'X509_user_identity=%s' % file_identity, realm.user_princ])
realm.kinit(realm.user_princ,
            flags=['-X', 'X509_user_identity=%s' % file_identity])
realm.klist(realm.user_princ)
realm.run([kvno, realm.host_princ])

# Run the basic test - PKINIT with FILE: identity, with a password on the key,
# supplied by the prompter.
# Expect failure if the responder does nothing, and we have no prompter.
realm.run(['./responder', '-x', 'pkinit={"%s": 0}' % file_enc_identity,
          '-X', 'X509_user_identity=%s' % file_enc_identity, realm.user_princ],
          expected_code=2)
realm.kinit(realm.user_princ,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -93,6 +93,11 @@
 if 'KDC policy rejects request' not in out:
     fail('Wrong error for restricted anonymous PKINIT')
 
+# Regression test for #8458: S4U2Self requests crash the KDC if
+# anonymous is restricted.
+realm.kinit(realm.host_princ, flags=['-k'])
+realm.run([kvno, '-U', 'user', realm.host_princ])
+
 # Go back to a normal KDC and disable anonymous PKINIT.
 realm.stop_kdc()
 realm.start_kdc()
```
