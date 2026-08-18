# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 5235_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5235_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 157-202 of the vulnerable file.


    # strip all spaces/tabs
    line = line.strip()

    # init return code
    returncode = 0

    # This logic is kept crudely simple on purpose.
    # At most we might match the same stanza twice
    # (for e.g. "'a'", 'a') but the converse would
    # require detecting single quotation stanzas
    # nested within double quotes and vice versa
    relist = re.findall(r'[^=]\"(.+)\"', line)
    relist2 = re.findall(r'[^=]\'(.+)\'', line)
    relist = relist + relist2
    for item in relist:
        if os.path.exists(item):
            ret_check_path, conf = check_path(item, conf, strict=strict)
            returncode += ret_check_path

    # ignore quoted text
    line = re.sub(r'\"(.+?)\"', '', line)
    line = re.sub(r'\'(.+?)\'', '', line)

    if re.findall('[:cntrl:].*\n', line):
        ret, conf = warn_count('syntax',
                               oline,
                               conf,
                               strict=strict,
                               ssh=ssh)
        return ret, conf

    for item in conf['forbidden']:
        # allow '&&' and '||' even if singles are forbidden
        if item in ['&', '|']:
            if re.findall("[^\%s]\%s[^\%s]" % (item, item, item), line):
                ret, conf = warn_count('syntax',
                                       oline,
                                       conf,
                                       strict=strict,
                                       ssh=ssh)
                return ret, conf
        else:
            if item in line:
                ret, conf = warn_count('syntax',
                                       oline,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -174,12 +174,9 @@
             ret_check_path, conf = check_path(item, conf, strict=strict)
             returncode += ret_check_path
 
-    # ignore quoted text
-    line = re.sub(r'\"(.+?)\"', '', line)
-    line = re.sub(r'\'(.+?)\'', '', line)
-
-    if re.findall('[:cntrl:].*\n', line):
-        ret, conf = warn_count('syntax',
+    # parse command line for control characters, and warn user
+    if re.findall(r'[\x01-\x1F\x7F]', oline):
+        ret, conf = warn_count('control char',
                                oline,
                                conf,
                                strict=strict,
```
