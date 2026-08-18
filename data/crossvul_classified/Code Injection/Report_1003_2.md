# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in shell
**Pair ID:** 1003_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1003_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```bash
Lines 839-858 of the vulnerable file.

then
    log_error -u2 "failed to capture subshell output when closing fd: case 2"
fi

actual=$(get_value 3)
if [[ $actual != $expected ]]
then
    log_error -u2 "failed to capture subshell output when closing fd: case 3"
fi

builtin -d echo
# Check if redirections work if backticks are nested inside $()
foo=$(print `echo bar`)
[[ $foo == "bar" ]] || log_error 'Redirections do not work if backticks are nested inside $()'

# Buffer boundary tests
for exp in 65535 65536
do    got=$($SHELL -c 'x=$(printf "%.*c" '$exp' x); print ${#x}' 2>&1)
    [[ $got == $exp ]] || log_error "large command substitution failed" "$exp" "$got"
done
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -856,3 +856,26 @@
 do    got=$($SHELL -c 'x=$(printf "%.*c" '$exp' x); print ${#x}' 2>&1)
     [[ $got == $exp ]] || log_error "large command substitution failed" "$exp" "$got"
 done
+
+# ==========
+# Verify that importing untrusted env vars does not allow evaluating arbitrary expressions but does
+# recognize all integer literals recognized by ksh.
+expect=8
+actual=$(env SHLVL='7' $SHELL -c 'echo $SHLVL')
+[[ $actual == $expect ]] || log_error "decimal int literal not recognized" "$expect" "$actual"
+
+expect=14
+actual=$(env SHLVL='013' $SHELL -c 'echo $SHLVL')
+[[ $actual == $expect ]] || log_error "leading zeros int literal not recognized" "$expect" "$actual"
+
+expect=4
+actual=$(env SHLVL='2#11' $SHELL -c 'echo $SHLVL')
+[[ $actual == $expect ]] || log_error "base#value int literal not recognized" "$expect" "$actual"
+
+expect=12
+actual=$(env SHLVL='16#B' $SHELL -c 'echo $SHLVL')
+[[ $actual == $expect ]] || log_error "base#value int literal not recognized" "$expect" "$actual"
+
+expect=1
+actual=$(env SHLVL="2#11+x[\$($bin_echo DANGER WILL ROBINSON >&2)0]" $SHELL -c 'echo $SHLVL')
+[[ $actual == $expect ]] || log_error "expression allowed on env var import" "$expect" "$actual"
```
