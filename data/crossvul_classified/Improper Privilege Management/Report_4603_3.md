# CrossVul Fix Pair: Improper Privilege Management in shell
**Pair ID:** 4603_3
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4603_3`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```bash
Lines 52-90 of the vulnerable file.

  # Change permissions so that the user that will run the MySQL daemon
  # owns all database files.
  chown -R -f %{mysqld_user}:%{mysqld_group} $datadir

  if [ ! -e $datadir/mysql ]; then
    # Create data directory
    mkdir -p $datadir

    # Initiate databases
    %{_bindir}/mysql_install_db --rpm --user=%{mysqld_user}
  fi

  # Change permissions again to fix any new files.
  chown -R %{mysqld_user}:%{mysqld_group} $datadir

  # Fix permissions for the permission database so that only the user
  # can read them.
  chmod -R og-rw $datadir/mysql
fi

# Set correct filesystem ownership/permissions for the PAM v2 plugin
chown %{mysqld_group} /usr/lib*/mysql/plugin/auth_pam_tool_dir
chmod 0700            /usr/lib*/mysql/plugin/auth_pam_tool_dir
chown 0               /usr/lib*/mysql/plugin/auth_pam_tool_dir/auth_pam_tool
chmod 04755           /usr/lib*/mysql/plugin/auth_pam_tool_dir/auth_pam_tool

# install SELinux files - but don't override existing ones
SETARGETDIR=/etc/selinux/targeted/src/policy
SEDOMPROG=$SETARGETDIR/domains/program
SECONPROG=$SETARGETDIR/file_contexts/program

if [ -x /usr/sbin/semodule ] ; then
  /usr/sbin/semodule -i /usr/share/mysql/policy/selinux/mariadb.pp
fi

if [ -x sbin/restorecon ] ; then
	sbin/restorecon -R var/lib/mysql
fi

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -69,11 +69,8 @@
   chmod -R og-rw $datadir/mysql
 fi
 
-# Set correct filesystem ownership/permissions for the PAM v2 plugin
-chown %{mysqld_group} /usr/lib*/mysql/plugin/auth_pam_tool_dir
-chmod 0700            /usr/lib*/mysql/plugin/auth_pam_tool_dir
-chown 0               /usr/lib*/mysql/plugin/auth_pam_tool_dir/auth_pam_tool
-chmod 04755           /usr/lib*/mysql/plugin/auth_pam_tool_dir/auth_pam_tool
+# Set the correct filesystem ownership for the PAM v2 plugin
+chown %{mysqld_user} /usr/lib*/mysql/plugin/auth_pam_tool_dir
 
 # install SELinux files - but don't override existing ones
 SETARGETDIR=/etc/selinux/targeted/src/policy
```
