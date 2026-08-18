# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in shell
**Pair ID:** 1664_7
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1664_7`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```bash
Lines 72-112 of the vulnerable file.

	. /etc/rc.status
	rc_reset
	my_rc_status_v()
	{
		res=$?
		[ $res -eq 0 ] || false
		rc_status -v
		my_rc_status_all=$(($my_rc_status_all || $res))
	}
fi

# pull in sysconfig settings                                                                  
if [ -f /etc/sysconfig/opafm.env ]; then
    . /etc/sysconfig/opafm.env
fi

my_rc_status_all=0
my_rc_exit()     { exit $my_rc_status_all; }
my_rc_status()   { my_rc_status_all=$(($my_rc_status_all || $?)); }

temp=/tmp/ifsfm$$

trap "rm -rf $tempdir; exit 1" 1 2 3 9 1

CONFIG_DIR=/etc/sysconfig
CONFIG_FILE=$CONFIG_DIR/opafm.xml	# opafm.info can override
MAX_INSTANCE=7	# largest instance number, for when config file bad

cmd=$1
force=n	# flag to force start even if running
quiet=n	# don't show per manager messages on stop, used by install
[ "$cmd" = "quietstop" ] && quiet=y	# special case for install
shift

Usage()
{
	echo "Usage: $0 [start|stop|restart|reload|sweep|status]" >&2
	echo "               [-i instance] [-f] [component|compname|insname] ..." >&2
	echo " start       - start the selected instances/managers" >&2
	echo " stop        - stop the selected instances/managers" >&2
	echo " restart     - restart (eg. stop then start) the selected instances/managers" >&2
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -89,7 +89,7 @@
 my_rc_exit()     { exit $my_rc_status_all; }
 my_rc_status()   { my_rc_status_all=$(($my_rc_status_all || $?)); }
 
-temp=/tmp/ifsfm$$
+temp=$(mktemp "/tmp/ifsfmXXXXX")
 
 trap "rm -rf $tempdir; exit 1" 1 2 3 9 1
 
```
