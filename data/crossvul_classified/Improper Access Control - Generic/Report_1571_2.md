# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 1571_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1571_2`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 271-311 of the vulnerable file.

      /* Add password to ds_args before overwriting the arg with x's */
      add_one_option(&ds_args, opt, argument);
      while (*argument)
        *argument++= 'x';                       /* Destroy argument */
      tty_password= 0;
    }
    break;

  case 't':
    my_stpnmov(opt_tmpdir, argument, sizeof(opt_tmpdir));
    add_option= FALSE;
    break;

  case 'k':                                     /* --version-check */
  case 'v': /* --verbose   */
  case 'f': /* --force     */
  case 's':                                     /* --upgrade-system-tables */
  case OPT_WRITE_BINLOG:                        /* --write-binlog */
    add_option= FALSE;
    break;

  case 'h': /* --host */
  case 'W': /* --pipe */
  case 'P': /* --port */
  case 'S': /* --socket */
  case OPT_MYSQL_PROTOCOL: /* --protocol */
  case OPT_SHARED_MEMORY_BASE_NAME: /* --shared-memory-base-name */
  case OPT_PLUGIN_DIR:                          /* --plugin-dir */
  case OPT_DEFAULT_AUTH:                        /* --default-auth */
    add_one_option(&conn_args, opt, argument);
    break;
  }

  if (add_option)
  {
    /*
      This is an option that is accpted by mysql_upgrade just so
      it can be passed on to "mysql" and "mysqlcheck"
      Save it in the ds_args string
    */
    add_one_option(&ds_args, opt, argument);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -288,7 +288,7 @@
   case OPT_WRITE_BINLOG:                        /* --write-binlog */
     add_option= FALSE;
     break;
-
+#include <sslopt-case.h>
   case 'h': /* --host */
   case 'W': /* --pipe */
   case 'P': /* --port */
```
