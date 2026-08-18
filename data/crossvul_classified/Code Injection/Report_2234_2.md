# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in python
**Pair ID:** 2234_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2234_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```python
Lines 105-135 of the vulnerable file.

        pathmd5 = utils.md5s(path)
        remote_md5 = self.runner._remote_md5(conn, tmp, dest)

        if pathmd5 != remote_md5:
            resultant = file(path).read()
            if self.runner.diff:
                dest_result = self.runner._execute_module(conn, tmp, 'slurp', "path=%s" % dest, inject=inject, persist_files=True)
                if 'content' in dest_result.result:
                    dest_contents = dest_result.result['content']
                    if dest_result.result['encoding'] == 'base64':
                        dest_contents = base64.b64decode(dest_contents)
                    else:
                        raise Exception("unknown encoding, failed: %s" % dest_result.result)
            xfered = self.runner._transfer_str(conn, tmp, 'src', resultant)

            # fix file permissions when the copy is done as a different user
            if self.runner.sudo and self.runner.sudo_user != 'root':
                self.runner._low_level_exec_command(conn, "chmod a+r %s" % xfered, tmp)

            # run the copy module
            module_args = "%s src=%s dest=%s original_basename=%s" % (module_args, pipes.quote(xfered), pipes.quote(dest), pipes.quote(os.path.basename(src)))

            if self.runner.noop_on_check(inject):
                return ReturnData(conn=conn, comm_ok=True, result=dict(changed=True), diff=dict(before_header=dest, after_header=src, after=resultant))
            else:
                res = self.runner._execute_module(conn, tmp, 'copy', module_args, inject=inject)
                res.diff = dict(after=resultant)
                return res
        else:
            module_args = "%s src=%s dest=%s original_basename=%s" % (module_args, pipes.quote(xfered), pipes.quote(dest), pipes.quote(os.path.basename(src)))
            return self.runner._execute_module(conn, tmp, 'file', module_args, inject=inject)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -122,14 +122,25 @@
                 self.runner._low_level_exec_command(conn, "chmod a+r %s" % xfered, tmp)
 
             # run the copy module
-            module_args = "%s src=%s dest=%s original_basename=%s" % (module_args, pipes.quote(xfered), pipes.quote(dest), pipes.quote(os.path.basename(src)))
+            new_module_args = dict(
+                src=xfered,
+                dest=dest,
+                original_basename=os.path.basename(src),
+            )
+            module_args_tmp = utils.merge_module_args(module_args, new_module_args)
 
             if self.runner.noop_on_check(inject):
                 return ReturnData(conn=conn, comm_ok=True, result=dict(changed=True), diff=dict(before_header=dest, after_header=src, after=resultant))
             else:
-                res = self.runner._execute_module(conn, tmp, 'copy', module_args, inject=inject)
+                res = self.runner._execute_module(conn, tmp, 'copy', module_args_tmp, inject=inject)
                 res.diff = dict(after=resultant)
                 return res
         else:
-            module_args = "%s src=%s dest=%s original_basename=%s" % (module_args, pipes.quote(xfered), pipes.quote(dest), pipes.quote(os.path.basename(src)))
-            return self.runner._execute_module(conn, tmp, 'file', module_args, inject=inject)
+            new_module_args = dict(
+                src=xfered,
+                dest=dest,
+                original_basename=os.path.basename(src),
+            )
+            module_args_tmp = utils.merge_module_args(module_args, new_module_args)
+
+            return self.runner._execute_module(conn, tmp, 'file', module_args_tmp, inject=inject)
```
