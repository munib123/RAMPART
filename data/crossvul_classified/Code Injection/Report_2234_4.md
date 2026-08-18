# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in python
**Pair ID:** 2234_4
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2234_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```python
Lines 100-131 of the vulnerable file.

            # if showing diffs, we need to get the remote value
            dest_contents = ''

            if self.runner.diff:
                # using persist_files to keep the temp directory around to avoid needing to grab another
                dest_result = self.runner._execute_module(conn, tmp, 'slurp', "path=%s" % dest, inject=inject, persist_files=True)
                if 'content' in dest_result.result:
                    dest_contents = dest_result.result['content']
                    if dest_result.result['encoding'] == 'base64':
                        dest_contents = base64.b64decode(dest_contents)
                    else:
                        raise Exception("unknown encoding, failed: %s" % dest_result.result)
 
            xfered = self.runner._transfer_str(conn, tmp, 'source', resultant)

            # fix file permissions when the copy is done as a different user
            if self.runner.sudo and self.runner.sudo_user != 'root':
                self.runner._low_level_exec_command(conn, "chmod a+r %s" % xfered, tmp)

            # run the copy module
            module_args = "%s src=%s dest=%s original_basename=%s" % (module_args, pipes.quote(xfered), pipes.quote(dest), pipes.quote(os.path.basename(source)))

            if self.runner.noop_on_check(inject):
                return ReturnData(conn=conn, comm_ok=True, result=dict(changed=True), diff=dict(before_header=dest, after_header=source, before=dest_contents, after=resultant))
            else:
                res = self.runner._execute_module(conn, tmp, 'copy', module_args, inject=inject, complex_args=complex_args)
                if res.result.get('changed', False):
                    res.diff = dict(before=dest_contents, after=resultant)
                return res
        else:
            return self.runner._execute_module(conn, tmp, 'file', module_args, inject=inject, complex_args=complex_args)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -117,12 +117,17 @@
                 self.runner._low_level_exec_command(conn, "chmod a+r %s" % xfered, tmp)
 
             # run the copy module
-            module_args = "%s src=%s dest=%s original_basename=%s" % (module_args, pipes.quote(xfered), pipes.quote(dest), pipes.quote(os.path.basename(source)))
+            new_module_args = dict(
+               src=xfered,
+               dest=dest,
+               original_basename=os.path.basename(source),
+            )
+            module_args_tmp = utils.merge_module_args(module_args, new_module_args)
 
             if self.runner.noop_on_check(inject):
                 return ReturnData(conn=conn, comm_ok=True, result=dict(changed=True), diff=dict(before_header=dest, after_header=source, before=dest_contents, after=resultant))
             else:
-                res = self.runner._execute_module(conn, tmp, 'copy', module_args, inject=inject, complex_args=complex_args)
+                res = self.runner._execute_module(conn, tmp, 'copy', module_args_tmp, inject=inject, complex_args=complex_args)
                 if res.result.get('changed', False):
                     res.diff = dict(before=dest_contents, after=resultant)
                 return res
```
