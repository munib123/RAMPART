# CrossVul Fix Pair: Improper Privilege Management in shell
**Pair ID:** 4603_2
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4603_2`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```bash
Lines 461-501 of the vulnerable file.

    if ! `mkdir -p "$dir"`
    then
      echo "Fatal error Can't create database directory '$dir'"
      link_to_help
      exit 1
    fi
    chmod 700 "$dir"
  fi
  if test -n "$user"
  then
    chown $user "$dir"
    if test $? -ne 0
    then
      echo "Cannot change ownership of the database directories to the '$user'"
      echo "user.  Check that you have the necessary permissions and try again."
      exit 1
    fi
  fi
done

if test -n "$user"
then
  chown $user "$pamtooldir/auth_pam_tool_dir" && \
  chmod 0700 "$pamtooldir/auth_pam_tool_dir"
  if test $? -ne 0
  then
      echo "Cannot change ownership of the '$pamtooldir/auth_pam_tool_dir' directory"
      echo " to the '$user' user. Check that you have the necessary permissions and try again."
      exit 1
  fi
  if test -z "$srcdir"
  then
    chown 0 "$pamtooldir/auth_pam_tool_dir/auth_pam_tool" && \
    chmod 04755 "$pamtooldir/auth_pam_tool_dir/auth_pam_tool"
    if test $? -ne 0
    then
        echo "Couldn't set an owner to '$pamtooldir/auth_pam_tool_dir/auth_pam_tool'."
        echo " It must be root, the PAM authentication plugin doesn't work otherwise.."
        echo
    fi
  fi
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -478,16 +478,8 @@
   fi
 done
 
-if test -n "$user"
-then
-  chown $user "$pamtooldir/auth_pam_tool_dir" && \
-  chmod 0700 "$pamtooldir/auth_pam_tool_dir"
-  if test $? -ne 0
-  then
-      echo "Cannot change ownership of the '$pamtooldir/auth_pam_tool_dir' directory"
-      echo " to the '$user' user. Check that you have the necessary permissions and try again."
-      exit 1
-  fi
+if test -n "$user" -a "$in_rpm" -eq 0
+then
   if test -z "$srcdir"
   then
     chown 0 "$pamtooldir/auth_pam_tool_dir/auth_pam_tool" && \
@@ -499,6 +491,14 @@
         echo
     fi
   fi
+  chown $user "$pamtooldir/auth_pam_tool_dir" && \
+  chmod 0700 "$pamtooldir/auth_pam_tool_dir"
+  if test $? -ne 0
+  then
+      echo "Cannot change ownership of the '$pamtooldir/auth_pam_tool_dir' directory"
+      echo " to the '$user' user. Check that you have the necessary permissions and try again."
+      exit 1
+  fi
   args="$args --user=$user"
 fi
 
```
