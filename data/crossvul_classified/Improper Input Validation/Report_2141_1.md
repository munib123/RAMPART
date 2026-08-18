# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 2141_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2141_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 480-520 of the vulnerable file.

        cmd = cmd.strip()

        sudoable = True
        if module_name == "accelerate":
            # always run the accelerate module as the user
            # specified in the play, not the sudo_user
            sudoable = False

        if self.su:
            res = self._low_level_exec_command(conn, cmd, tmp, su=True, in_data=in_data)
        else:
            res = self._low_level_exec_command(conn, cmd, tmp, sudoable=sudoable, in_data=in_data)

        if "tmp" in tmp and not C.DEFAULT_KEEP_REMOTE_FILES and not persist_files and delete_remote_tmp:
            if (self.sudo and self.sudo_user != 'root') or (self.su and self.su_user != 'root'):
            # not sudoing to root, so maybe can't delete files as that other user
            # have to clean up temp files as original user in a second step
                cmd2 = conn.shell.remove(tmp, recurse=True)
                self._low_level_exec_command(conn, cmd2, tmp, sudoable=False)

        data = utils.parse_json(res['stdout'])
        if 'parsed' in data and data['parsed'] == False:
            data['msg'] += res['stderr']
        return ReturnData(conn=conn, result=data)

    # *****************************************************

    def _executor(self, host, new_stdin):
        ''' handler for multiprocessing library '''

        try:
            fileno = sys.stdin.fileno()
        except ValueError:
            fileno = None

        try:
            self._new_stdin = new_stdin
            if not new_stdin and fileno is not None:
                try:
                    self._new_stdin = os.fdopen(os.dup(fileno))
                except OSError, e:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -497,7 +497,7 @@
                 cmd2 = conn.shell.remove(tmp, recurse=True)
                 self._low_level_exec_command(conn, cmd2, tmp, sudoable=False)
 
-        data = utils.parse_json(res['stdout'])
+        data = utils.parse_json(res['stdout'], from_remote=True)
         if 'parsed' in data and data['parsed'] == False:
             data['msg'] += res['stderr']
         return ReturnData(conn=conn, result=data)
```
