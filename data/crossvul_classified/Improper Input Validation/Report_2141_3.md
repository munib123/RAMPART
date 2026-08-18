# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 2141_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2141_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 296-336 of the vulnerable file.

    if os.path.islink(basedir):
        basedir = unfrackpath(basedir)
        template2 = os.path.join(basedir, dirname, source)
    else:
        template2 = os.path.join(basedir, '..', dirname, source)
    source2 = path_dwim(basedir, template2)
    if os.path.exists(source2):
        return source2
    obvious_local_path = path_dwim(playbook_base, source)
    if os.path.exists(obvious_local_path):
        return obvious_local_path
    if check:
        raise errors.AnsibleError("input file not found at %s or %s" % (source2, obvious_local_path))
    return source2 # which does not exist

def json_loads(data):
    ''' parse a JSON string and return a data structure '''

    return json.loads(data)

def parse_json(raw_data):
    ''' this version for module return data only '''

    orig_data = raw_data

    # ignore stuff like tcgetattr spewage or other warnings
    data = filter_leading_non_json_lines(raw_data)

    try:
        return json.loads(data)
    except:
        # not JSON, but try "Baby JSON" which allows many of our modules to not
        # require JSON and makes writing modules in bash much simpler
        results = {}
        try:
            tokens = shlex.split(data)
        except:
            print "failed to parse json: "+ data
            raise

        for t in tokens:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -313,7 +313,38 @@
 
     return json.loads(data)
 
-def parse_json(raw_data):
+def _clean_data(orig_data):
+    ''' remove template tags from a string '''
+    data = orig_data
+    if isinstance(orig_data, basestring):
+        for pattern,replacement in (('{{','{#'), ('}}','#}'), ('{%','{#'), ('%}','#}')):
+            data = data.replace(pattern, replacement)
+    return data
+
+def _clean_data_struct(orig_data):
+    '''
+    walk a complex data structure, and use _clean_data() to
+    remove any template tags that may exist
+    '''
+    if isinstance(orig_data, dict):
+        data = orig_data.copy()
+        for key in data:
+            new_key = _clean_data_struct(key)
+            new_val = _clean_data_struct(data[key])
+            if key != new_key:
+                del data[key]
+            data[new_key] = new_val
+    elif isinstance(orig_data, list):
+        data = orig_data[:]
+        for i in range(0, len(data)):
+            data[i] = _clean_data_struct(data[i])
+    elif isinstance(orig_data, basestring):
+        data = _clean_data(orig_data)
+    else:
+        data = orig_data
+    return data
+
+def parse_json(raw_data, from_remote=False):
     ''' this version for module return data only '''
 
     orig_data = raw_data
@@ -322,7 +353,7 @@
     data = filter_leading_non_json_lines(raw_data)
 
     try:
-        return json.loads(data)
+        results = json.loads(data)
     except:
         # not JSON, but try "Baby JSON" which allows many of our modules to not
         # require JSON and makes writing modules in bash much simpler
@@ -332,7 +363,6 @@
         except:
             print "failed to parse json: "+ data
             raise
-
         for t in tokens:
             if "=" not in t:
                 raise errors.AnsibleError("failed to parse: %s" % orig_data)
@@ -347,7 +377,11 @@
             results[key] = value
         if len(results.keys()) == 0:
             return { "failed" : True, "parsed" : False, "msg" : orig_data }
-        return results
+
+    if from_remote:
+        results = _clean_data_struct(results)
+
+    return results
 
 def smush_braces(data):
     ''' smush Jinaj2 braces so unresolved templates like {{ foo }} don't get parsed weird by key=value code '''
```
