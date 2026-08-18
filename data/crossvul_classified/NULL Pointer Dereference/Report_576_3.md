# CrossVul Fix Pair: NULL Pointer Dereference in python
**Pair ID:** 576_3
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `576_3`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```python
Lines 186-226 of the vulnerable file.

kldaputil(['create', '-s', '-P', 'master', '-subtrees', 'cn=t2,cn=krb5',
           '-containerref', 'cn=t2,cn=krb5', '-sscope', 'one',
           '-maxtktlife', '5min', '-maxrenewlife', '10min', '-allow_svr'])

# Modify the realm, exercising overlapping subtree pruning.
kldaputil(['modify', '-subtrees',
           'cn=x,cn=t1,cn=krb5:cn=t1,cn=krb5:cn=t2,cn=krb5:cn=y,cn=t2,cn=krb5',
           '-containerref', 'cn=t1,cn=krb5', '-sscope', 'sub',
           '-maxtktlife', '5hour', '-maxrenewlife', '10hour', '+allow_svr'])

out = kldaputil(['list'])
if out != 'KRBTEST.COM\n':
    fail('Unexpected kdb5_ldap_util list output')

# Create a principal at a specified DN.  This is a little dodgy
# because we're sticking a krbPrincipalAux objectclass onto a subtree
# krbContainer, but it works and it avoids having to load core.schema
# in the test LDAP server.
realm.run([kadminl, 'ank', '-randkey', '-x', 'dn=cn=krb5', 'princ1'],
          expected_code=1, expected_msg='DN is out of the realm subtree')
realm.run([kadminl, 'ank', '-randkey', '-x', 'dn=cn=t2,cn=krb5', 'princ1'])
realm.run([kadminl, 'getprinc', 'princ1'], expected_msg='Principal: princ1')
realm.run([kadminl, 'ank', '-randkey', '-x', 'dn=cn=t2,cn=krb5', 'again'],
          expected_code=1, expected_msg='ldap object is already kerberized')
# Check that we can't set linkdn on a non-standalone object.
realm.run([kadminl, 'modprinc', '-x', 'linkdn=cn=t1,cn=krb5', 'princ1'],
          expected_code=1, expected_msg='link information can not be set')

# Create a principal with a specified linkdn.
realm.run([kadminl, 'ank', '-randkey', '-x', 'linkdn=cn=krb5', 'princ2'],
          expected_code=1, expected_msg='DN is out of the realm subtree')
realm.run([kadminl, 'ank', '-randkey', '-x', 'linkdn=cn=t1,cn=krb5', 'princ2'])
# Check that we can't reset linkdn.
realm.run([kadminl, 'modprinc', '-x', 'linkdn=cn=t2,cn=krb5', 'princ2'],
          expected_code=1, expected_msg='kerberos principal is already linked')

# Create a principal with a specified containerdn.
realm.run([kadminl, 'ank', '-randkey', '-x', 'containerdn=cn=krb5', 'princ3'],
          expected_code=1, expected_msg='DN is out of the realm subtree')
realm.run([kadminl, 'ank', '-randkey', '-x', 'containerdn=cn=t1,cn=krb5',
           'princ3'])
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -203,6 +203,12 @@
 # in the test LDAP server.
 realm.run([kadminl, 'ank', '-randkey', '-x', 'dn=cn=krb5', 'princ1'],
           expected_code=1, expected_msg='DN is out of the realm subtree')
+# Check that the DN container check is a hierarchy test, not a simple
+# suffix match (CVE-2018-5730).  We expect this operation to fail
+# either way (because "xcn" isn't a valid DN tag) but the container
+# check should happen before the DN is parsed.
+realm.run([kadminl, 'ank', '-randkey', '-x', 'dn=xcn=t1,cn=krb5', 'princ1'],
+          expected_code=1, expected_msg='DN is out of the realm subtree')
 realm.run([kadminl, 'ank', '-randkey', '-x', 'dn=cn=t2,cn=krb5', 'princ1'])
 realm.run([kadminl, 'getprinc', 'princ1'], expected_msg='Principal: princ1')
 realm.run([kadminl, 'ank', '-randkey', '-x', 'dn=cn=t2,cn=krb5', 'again'],
@@ -226,6 +232,11 @@
            'princ3'])
 realm.run([kadminl, 'modprinc', '-x', 'containerdn=cn=t2,cn=krb5', 'princ3'],
           expected_code=1, expected_msg='containerdn option not supported')
+# Verify that containerdn is checked when linkdn is also supplied
+# (CVE-2018-5730).
+realm.run([kadminl, 'ank', '-randkey', '-x', 'containerdn=cn=krb5',
+           '-x', 'linkdn=cn=t2,cn=krb5', 'princ4'], expected_code=1,
+          expected_msg='DN is out of the realm subtree')
 
 # Create and modify a ticket policy.
 kldaputil(['create_policy', '-maxtktlife', '3hour', '-maxrenewlife', '6hour',
```
