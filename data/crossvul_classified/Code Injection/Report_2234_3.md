# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in python
**Pair ID:** 2234_3
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2234_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```python
Lines 221-262 of the vulnerable file.

                if not raw:
                    conn.put_file(source_full, tmp_src)
                else:
                    conn.put_file(source_full, dest_file)

                # We have copied the file remotely and no longer require our content_tempfile
                self._remove_tempfile_if_content_defined(content, content_tempfile)

                # fix file permissions when the copy is done as a different user
                if self.runner.sudo and self.runner.sudo_user != 'root' and not raw:
                    self.runner._low_level_exec_command(conn, "chmod a+r %s" % tmp_src, tmp_path)

                if raw:
                    # Continue to next iteration if raw is defined.
                    continue

                # Run the copy module

                # src and dest here come after original and override them
                # we pass dest only to make sure it includes trailing slash in case of recursive copy
                module_args_tmp = "%s src=%s dest=%s original_basename=%s" % (module_args,
                                  pipes.quote(tmp_src), pipes.quote(dest), pipes.quote(source_rel))

                if self.runner.no_log:
                    module_args_tmp = "%s NO_LOG=True" % module_args_tmp

                module_return = self.runner._execute_module(conn, tmp_path, 'copy', module_args_tmp, inject=inject, complex_args=complex_args, delete_remote_tmp=delete_remote_tmp)
                module_executed = True

            else:
                # no need to transfer the file, already correct md5, but still need to call
                # the file module in case we want to change attributes
                self._remove_tempfile_if_content_defined(content, content_tempfile)

                if raw:
                    # Continue to next iteration if raw is defined.
                    # self.runner._remove_tmp_path(conn, tmp_path)
                    continue

                tmp_src = tmp_path + source_rel

                # Build temporary module_args.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -238,11 +238,16 @@
 
                 # src and dest here come after original and override them
                 # we pass dest only to make sure it includes trailing slash in case of recursive copy
-                module_args_tmp = "%s src=%s dest=%s original_basename=%s" % (module_args,
-                                  pipes.quote(tmp_src), pipes.quote(dest), pipes.quote(source_rel))
+                new_module_args = dict(
+                    src=tmp_src,
+                    dest=dest,
+                    original_basename=source_rel
+                )
 
                 if self.runner.no_log:
-                    module_args_tmp = "%s NO_LOG=True" % module_args_tmp
+                    new_module_args['NO_LOG'] = True
+
+                module_args_tmp = utils.merge_module_args(module_args, new_module_args)
 
                 module_return = self.runner._execute_module(conn, tmp_path, 'copy', module_args_tmp, inject=inject, complex_args=complex_args, delete_remote_tmp=delete_remote_tmp)
                 module_executed = True
@@ -260,12 +265,16 @@
                 tmp_src = tmp_path + source_rel
 
                 # Build temporary module_args.
-                module_args_tmp = "%s src=%s original_basename=%s" % (module_args,
-                                  pipes.quote(tmp_src), pipes.quote(source_rel))
+                new_module_args = dict(
+                    src=tmp_src,
+                    dest=dest,
+                )
                 if self.runner.noop_on_check(inject):
-                    module_args_tmp = "%s CHECKMODE=True" % module_args_tmp
+                    new_module_args['CHECKMODE'] = True
                 if self.runner.no_log:
-                    module_args_tmp = "%s NO_LOG=True" % module_args_tmp
+                    new_module_args['NO_LOG'] = True
+
+                module_args_tmp = utils.merge_module_args(module_args, new_module_args)
 
                 # Execute the file module.
                 module_return = self.runner._execute_module(conn, tmp_path, 'file', module_args_tmp, inject=inject, complex_args=complex_args, delete_remote_tmp=delete_remote_tmp)
```
