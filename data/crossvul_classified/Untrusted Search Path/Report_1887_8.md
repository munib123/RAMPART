# CrossVul Fix Pair: Untrusted Search Path in shell
**Pair ID:** 1887_8
**Vulnerability Class:** Untrusted Search Path
**CWE:** CWE-426
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1887_8`)

## Vulnerability Information & PoC

## Description
Untrusted Search Path - This might allow attackers to execute their own programs, access unauthorized data files, or modify configuration in unexpected ways.

## Vulnerable Code
```bash
Lines 4-23 of the vulnerable file.


begin_test "does not look in current directory for git"
(
  set -e

  reponame="$(basename "$0" ".sh")"
  git init "$reponame"
  cd "$reponame"
  export PATH="$(echo "$PATH" | sed -e "s/:.:/:/g" -e "s/::/:/g")"

  printf "#!/bin/sh\necho exploit >&2\n" > git
  chmod +x git || true
  printf "echo exploit 1>&2\n" > git.bat

  # This needs to succeed.  If it fails, that could be because our malicious
  # "git" is broken but got invoked anyway.
  git lfs env > output.log 2>&1
  ! grep -q 'exploit' output.log
)
end_test
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,3 +21,41 @@
   ! grep -q 'exploit' output.log
 )
 end_test
+
+begin_test "does not look in current directory for git with credential helper"
+(
+  set -e
+
+  reponame="$(basename "$0" ".sh")-credentials"
+  setup_remote_repo "$reponame"
+
+  clone_repo "$reponame" credentials-1
+  export PATH="$(echo "$PATH" | sed -e "s/:.:/:/g" -e "s/::/:/g")"
+
+  printf "#!/bin/sh\necho exploit >&2\ntouch exploit\n" > git
+  chmod +x git || true
+  printf "echo exploit 1>&2\r\necho >exploit" > git.bat
+
+  git lfs track "*.dat"
+  printf abc > z.dat
+  git add z.dat
+  git add .gitattributes
+  git add git git.bat
+  git commit -m "Add files"
+
+  git push origin HEAD
+  cd ..
+
+  unset GIT_ASKPASS SSH_ASKPASS
+
+  # This needs to succeed.  If it fails, that could be because our malicious
+  # "git" is broken but got invoked anyway.
+  GIT_LFS_SKIP_SMUDGE=1 clone_repo "$reponame" credentials-2
+
+  git lfs pull | tee output.log
+
+  ! grep -q 'exploit' output.log
+  [ ! -f ../exploit ]
+  [ ! -f exploit ]
+)
+end_test
```
