# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in shell
**Pair ID:** 1664_8
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1664_8`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```bash
Lines 70-110 of the vulnerable file.


allow_invalid_config()
{
	if [ "$VALID_CONFIG" != "y" ]
	then
		echo "Will proceed assuming no more than $(($MAX_INSTANCE+1)) fm instances"
	fi
}

running_manager()
# $1 = instance number
# $2 = manager name in lowercase
{
	pgrep -f "$2 -e ${2}_$1" > /dev/null 2>&1
}

my_rc_status_all=0
my_rc_exit()     { exit $my_rc_status_all; }
my_rc_status()   { my_rc_status_all=$(($my_rc_status_all || $?)); }

temp=/tmp/ifsfm$$
invalid_config()
{
	local i

	VALID_CONFIG=n
	# set up some default instances to facilitate stop
	init_config
}

test_start()
{
	# $1=parameter name
	# $2=value, must be 0 or 1
	# test value is a valid start value (0 or 1)
	if [ "$2" -eq 0 -o "$2" -eq 1 ]
	then
		return 0
	else
		[ "$quiet" != y ] && echo "Error: $CONFIG_FILE Invalid $1 value: $2" >&2
		invalid_config
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -87,7 +87,7 @@
 my_rc_exit()     { exit $my_rc_status_all; }
 my_rc_status()   { my_rc_status_all=$(($my_rc_status_all || $?)); }
 
-temp=/tmp/ifsfm$$
+temp=$(mktemp "/tmp/ifsfmXXXXX")
 invalid_config()
 {
 	local i
```
