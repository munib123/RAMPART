# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in python
**Pair ID:** 1559_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1559_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```python
Lines 194-234 of the vulnerable file.

    LOG.debug('Writing initial config to %s...', path)
    tmp = '%s.tmp' % path
    with file(tmp, 'w') as f:
        cfg.write(f)
    try:
        os.rename(tmp, path)
    except OSError as e:
        if e.errno == errno.EEXIST:
            raise exc.ClusterExistsError(path)
        else:
            raise


def new_mon_keyring(args):
    LOG.debug('Creating a random mon key...')
    mon_keyring = '[mon.]\nkey = %s\ncaps mon = allow *\n' % generate_auth_key()

    keypath = '{name}.mon.keyring'.format(
        name=args.cluster,
        )

    LOG.debug('Writing monitor keyring to %s...', keypath)
    tmp = '%s.tmp' % keypath
    with file(tmp, 'w') as f:
        f.write(mon_keyring)
    try:
        os.rename(tmp, keypath)
    except OSError as e:
        if e.errno == errno.EEXIST:
            raise exc.ClusterExistsError(keypath)
        else:
            raise


@priority(10)
def make(parser):
    """
    Start deploying a new cluster, and write a CLUSTER.conf and keyring for it.
    """
    parser.add_argument(
        'mon',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -211,18 +211,21 @@
     keypath = '{name}.mon.keyring'.format(
         name=args.cluster,
         )
-
+    oldmask = os.umask(077)
     LOG.debug('Writing monitor keyring to %s...', keypath)
-    tmp = '%s.tmp' % keypath
-    with file(tmp, 'w') as f:
-        f.write(mon_keyring)
     try:
-        os.rename(tmp, keypath)
-    except OSError as e:
-        if e.errno == errno.EEXIST:
-            raise exc.ClusterExistsError(keypath)
-        else:
-            raise
+        tmp = '%s.tmp' % keypath
+        with open(tmp, 'w', 0600) as f:
+            f.write(mon_keyring)
+        try:
+            os.rename(tmp, keypath)
+        except OSError as e:
+            if e.errno == errno.EEXIST:
+                raise exc.ClusterExistsError(keypath)
+            else:
+                raise
+    finally:
+        os.umask(oldmask)
 
 
 @priority(10)
```
