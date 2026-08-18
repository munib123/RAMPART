# CrossVul Fix Pair: Improper Encoding or Escaping of Output in shell
**Pair ID:** 2439_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-116
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2439_1`)

## Vulnerability Information & PoC

## Description
Improper Encoding or Escaping of Output - Improper encoding or escaping can allow attackers to change the commands that are sent to another component, inserting malicious commands instead.

## Vulnerable Code
```bash
Lines 435-475 of the vulnerable file.

	test_cmp expected "$actual"
'

test_expect_success 'prompt - untracked files status indicator - not shown inside .git directory' '
	printf " (GIT_DIR!)" >expected &&
	(
		GIT_PS1_SHOWUNTRACKEDFILES=y &&
		cd .git &&
		__git_ps1 >"$actual"
	) &&
	test_cmp expected "$actual"
'

test_expect_success 'prompt - format string starting with dash' '
	printf -- "-master" >expected &&
	__git_ps1 "-%s" >"$actual" &&
	test_cmp expected "$actual"
'

test_expect_success 'prompt - pc mode' '
	printf "BEFORE: (master):AFTER" >expected &&
	printf "" >expected_output &&
	(
		__git_ps1 "BEFORE:" ":AFTER" >"$actual" &&
		test_cmp expected_output "$actual" &&
		printf "%s" "$PS1" >"$actual"
	) &&
	test_cmp expected "$actual"
'

test_expect_success 'prompt - bash color pc mode - branch name' '
	printf "BEFORE: (${c_green}master${c_clear}):AFTER" >expected &&
	(
		GIT_PS1_SHOWCOLORHINTS=y &&
		__git_ps1 "BEFORE:" ":AFTER" >"$actual"
		printf "%s" "$PS1" >"$actual"
	) &&
	test_cmp expected "$actual"
'

test_expect_success 'prompt - bash color pc mode - detached head' '
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -452,53 +452,53 @@
 '
 
 test_expect_success 'prompt - pc mode' '
-	printf "BEFORE: (master):AFTER" >expected &&
+	printf "BEFORE: (\${__git_ps1_branch_name}):AFTER\\nmaster" >expected &&
 	printf "" >expected_output &&
 	(
 		__git_ps1 "BEFORE:" ":AFTER" >"$actual" &&
 		test_cmp expected_output "$actual" &&
-		printf "%s" "$PS1" >"$actual"
+		printf "%s\\n%s" "$PS1" "${__git_ps1_branch_name}" >"$actual"
 	) &&
 	test_cmp expected "$actual"
 '
 
 test_expect_success 'prompt - bash color pc mode - branch name' '
-	printf "BEFORE: (${c_green}master${c_clear}):AFTER" >expected &&
+	printf "BEFORE: (${c_green}\${__git_ps1_branch_name}${c_clear}):AFTER\\nmaster" >expected &&
 	(
 		GIT_PS1_SHOWCOLORHINTS=y &&
 		__git_ps1 "BEFORE:" ":AFTER" >"$actual"
-		printf "%s" "$PS1" >"$actual"
+		printf "%s\\n%s" "$PS1" "${__git_ps1_branch_name}" >"$actual"
 	) &&
 	test_cmp expected "$actual"
 '
 
 test_expect_success 'prompt - bash color pc mode - detached head' '
-	printf "BEFORE: (${c_red}(%s...)${c_clear}):AFTER" $(git log -1 --format="%h" b1^) >expected &&
+	printf "BEFORE: (${c_red}\${__git_ps1_branch_name}${c_clear}):AFTER\\n(%s...)" $(git log -1 --format="%h" b1^) >expected &&
 	git checkout b1^ &&
 	test_when_finished "git checkout master" &&
 	(
 		GIT_PS1_SHOWCOLORHINTS=y &&
 		__git_ps1 "BEFORE:" ":AFTER" &&
-		printf "%s" "$PS1" >"$actual"
+		printf "%s\\n%s" "$PS1" "${__git_ps1_branch_name}" >"$actual"
 	) &&
 	test_cmp expected "$actual"
 '
 
 test_expect_success 'prompt - bash color pc mode - dirty status indicator - dirty worktree' '
-	printf "BEFORE: (${c_green}master${c_clear} ${c_red}*${c_clear}):AFTER" >expected &&
-	echo "dirty" >file &&
-	test_when_finished "git reset --hard" &&
-	(
-		GIT_PS1_SHOWDIRTYSTATE=y &&
-		GIT_PS1_SHOWCOLORHINTS=y &&
-		__git_ps1 "BEFORE:" ":AFTER" &&
-		printf "%s" "$PS1" >"$actual"
+	printf "BEFORE: (${c_green}\${__git_ps1_branch_name}${c_clear} ${c_red}*${c_clear}):AFTER\\nmaster" >expected &&
+	echo "dirty" >file &&
+	test_when_finished "git reset --hard" &&
+	(
+		GIT_PS1_SHOWDIRTYSTATE=y &&
+		GIT_PS1_SHOWCOLORHINTS=y &&
+		__git_ps1 "BEFORE:" ":AFTER" &&
+		printf "%s\\n%s" "$PS1" "${__git_ps1_branch_name}" >"$actual"
 	) &&
 	test_cmp expected "$actual"
 '
 
 test_expect_success 'prompt - bash color pc mode - dirty status indicator - dirty index' '
-	printf "BEFORE: (${c_green}master${c_clear} ${c_green}+${c_clear}):AFTER" >expected &&
+	printf "BEFORE: (${c_green}\${__git_ps1_branch_name}${c_clear} ${c_green}+${c_clear}):AFTER\\nmaster" >expected &&
 	echo "dirty" >file &&
 	test_when_finished "git reset --hard" &&
 	git add -u &&
@@ -506,13 +506,13 @@
 		GIT_PS1_SHOWDIRTYSTATE=y &&
 		GIT_PS1_SHOWCOLORHINTS=y &&
 		__git_ps1 "BEFORE:" ":AFTER" &&
-		printf "%s" "$PS1" >"$actual"
+		printf "%s\\n%s" "$PS1" "${__git_ps1_branch_name}" >"$actual"
 	) &&
 	test_cmp expected "$actual"
 '
 
 test_expect_success 'prompt - bash color pc mode - dirty status indicator - dirty index and worktree' '
-	printf "BEFORE: (${c_green}master${c_clear} ${c_red}*${c_green}+${c_clear}):AFTER" >expected &&
+	printf "BEFORE: (${c_green}\${__git_ps1_branch_name}${c_clear} ${c_red}*${c_green}+${c_clear}):AFTER\\nmaster" >expected &&
 	echo "dirty index" >file &&
 	test_when_finished "git reset --hard" &&
 	git add -u &&
@@ -521,25 +521,25 @@
 		GIT_PS1_SHOWCOLORHINTS=y &&
 		GIT_PS1_SHOWDIRTYSTATE=y &&
 		__git_ps1 "BEFORE:" ":AFTER" &&
-		printf "%s" "$PS1" >"$actual"
+		printf "%s\\n%s" "$PS1" "${__git_ps1_branch_name}" >"$actual"
 	) &&
 	test_cmp expected "$actual"
 '
 
 test_expect_success 'prompt - bash color pc mode - dirty status indicator - before root commit' '
-	printf "BEFORE: (${c_green}master${c_clear} ${c_green}#${c_clear}):AFTER" >expected &&
+	printf "BEFORE: (${c_green}\${__git_ps1_branch_name}${c_clear} ${c_green}#${c_clear}):AFTER\\nmaster" >expected &&
 	(
 		GIT_PS1_SHOWDIRTYSTATE=y &&
 		GIT_PS1_SHOWCOLORHINTS=y &&
 		cd otherrepo &&
 		__git_ps1 "BEFORE:" ":AFTER" &&
-		printf "%s" "$PS1" >"$actual"
+		printf "%s\\n%s" "$PS1" "${__git_ps1_branch_name}" >"$actual"
 	) &&
 	test_cmp expected "$actual"
 '
 
 test_expect_success 'prompt - bash color pc mode - inside .git directory' '
-	printf "BEFORE: (${c_green}GIT_DIR!${c_clear}):AFTER" >expected &&
+	printf "BEFORE: (${c_green}\${__git_ps1_branch_name}${c_clear}):AFTER\\nGIT_DIR!" >expected &&
 	echo "dirty" >file &&
 	test_when_finished "git reset --hard" &&
 	(
@@ -547,13 +547,13 @@
 		GIT_PS1_SHOWCOLORHINTS=y &&
 		cd .git &&
 		__git_ps1 "BEFORE:" ":AFTER" &&
-		printf "%s" "$PS1" >"$actual"
+		printf "%s\\n%s" "$PS1" "${__git_ps1_branch_name}" >"$actual"
 	) &&
 	test_cmp expected "$actual"
 '
 
 test_expect_success 'prompt - bash color pc mode - stash status indicator' '
-	printf "BEFORE: (${c_green}master${c_clear} ${c_lblue}\$${c_clear}):AFTER" >expected &&
+	printf "BEFORE: (${c_green}\${__git_ps1_branch_name}${c_clear} ${c_lblue}\$${c_clear}):AFTER\\nmaster" >expected &&
 	echo 2 >file &&
 	git stash &&
 	test_when_finished "git stash drop" &&
@@ -561,29 +561,29 @@
 		GIT_PS1_SHOWSTASHSTATE=y &&
 		GIT_PS1_SHOWCOLORHINTS=y &&
 		__git_ps1 "BEFORE:" ":AFTER" &&
-		printf "%s" "$PS1" >"$actual"
+		printf "%s\\n%s" "$PS1" "${__git_ps1_branch_name}" >"$actual"
 	) &&
 	test_cmp expected "$actual"
 '
 
 test_expect_success 'prompt - bash color pc mode - untracked files status indicator' '
-	printf "BEFORE: (${c_green}master${c_clear} ${c_red}%%${c_clear}):AFTER" >expected &&
+	printf "BEFORE: (${c_green}\${__git_ps1_branch_name}${c_clear} ${c_red}%%${c_clear}):AFTER\\nmaster" >expected &&
 	(
 		GIT_PS1_SHOWUNTRACKEDFILES=y &&
 		GIT_PS1_SHOWCOLORHINTS=y &&
 		__git_ps1 "BEFORE:" ":AFTER" &&
-		printf "%s" "$PS1" >"$actual"
+		printf "%s\\n%s" "$PS1" "${__git_ps1_branch_name}" >"$actual"
 	) &&
 	test_cmp expected "$actual"
 '
 
 test_expect_success 'prompt - zsh color pc mode' '
-	printf "BEFORE: (%%F{green}master%%f):AFTER" >expected &&
+	printf "BEFORE: (%%F{green}\${__git_ps1_branch_name}%%f):AFTER\\nmaster" >expected &&
 	(
 		ZSH_VERSION=5.0.0 &&
 		GIT_PS1_SHOWCOLORHINTS=y &&
 		__git_ps1 "BEFORE:" ":AFTER" >"$actual"
-		printf "%s" "$PS1" >"$actual"
+		printf "%s\\n%s" "$PS1" "${__git_ps1_branch_name}" >"$actual"
 	) &&
 	test_cmp expected "$actual"
 '
```
