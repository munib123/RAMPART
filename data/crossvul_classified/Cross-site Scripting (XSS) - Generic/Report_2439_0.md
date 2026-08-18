# CrossVul Fix Pair: Improper Encoding or Escaping of Output in shell
**Pair ID:** 2439_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-116
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2439_0`)

## Vulnerability Information & PoC

## Description
Improper Encoding or Escaping of Output - Improper encoding or escaping can allow attackers to change the commands that are sent to another component, inserting malicious commands instead.

## Vulnerable Code
```bash
Lines 190-230 of the vulnerable file.

			p=">" ;;
		*"	0") # behind upstream
			p="<" ;;
		*)	    # diverged from upstream
			p="<>" ;;
		esac
	else
		case "$count" in
		"") # no upstream
			p="" ;;
		"0	0") # equal to upstream
			p=" u=" ;;
		"0	"*) # ahead of upstream
			p=" u+${count#0	}" ;;
		*"	0") # behind upstream
			p=" u-${count%	0}" ;;
		*)	    # diverged from upstream
			p=" u+${count#*	}-${count%	*}" ;;
		esac
		if [[ -n "$count" && -n "$name" ]]; then
			p="$p $(git rev-parse --abbrev-ref "$upstream" 2>/dev/null)"
		fi
	fi

}

# Helper function that is meant to be called from __git_ps1.  It
# injects color codes into the appropriate gitstring variables used
# to build a gitstring.
__git_ps1_colorize_gitstring ()
{
	if [[ -n ${ZSH_VERSION-} ]]; then
		local c_red='%F{red}'
		local c_green='%F{green}'
		local c_lblue='%F{blue}'
		local c_clear='%f'
	else
		# Using \[ and \] around colors is necessary to prevent
		# issues with command line editing/browsing/completion!
		local c_red='\[\e[31m\]'
		local c_green='\[\e[32m\]'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -207,7 +207,18 @@
 			p=" u+${count#*	}-${count%	*}" ;;
 		esac
 		if [[ -n "$count" && -n "$name" ]]; then
-			p="$p $(git rev-parse --abbrev-ref "$upstream" 2>/dev/null)"
+			__git_ps1_upstream_name=$(git rev-parse \
+				--abbrev-ref "$upstream" 2>/dev/null)
+			if [ $pcmode = yes ]; then
+				# see the comments around the
+				# __git_ps1_branch_name variable below
+				p="$p \${__git_ps1_upstream_name}"
+			else
+				p="$p ${__git_ps1_upstream_name}"
+				# not needed anymore; keep user's
+				# environment clean
+				unset __git_ps1_upstream_name
+			fi
 		fi
 	fi
 
@@ -438,8 +449,27 @@
 		__git_ps1_colorize_gitstring
 	fi
 
+	b=${b##refs/heads/}
+	if [ $pcmode = yes ]; then
+		# In pcmode (and only pcmode) the contents of
+		# $gitstring are subject to expansion by the shell.
+		# Avoid putting the raw ref name in the prompt to
+		# protect the user from arbitrary code execution via
+		# specially crafted ref names (e.g., a ref named
+		# '$(IFS=_;cmd=sudo_rm_-rf_/;$cmd)' would execute
+		# 'sudo rm -rf /' when the prompt is drawn).  Instead,
+		# put the ref name in a new global variable (in the
+		# __git_ps1_* namespace to avoid colliding with the
+		# user's environment) and reference that variable from
+		# PS1.
+		__git_ps1_branch_name=$b
+		# note that the $ is escaped -- the variable will be
+		# expanded later (when it's time to draw the prompt)
+		b="\${__git_ps1_branch_name}"
+	fi
+
 	local f="$w$i$s$u"
-	local gitstring="$c${b##refs/heads/}${f:+$z$f}$r$p"
+	local gitstring="$c$b${f:+$z$f}$r$p"
 
 	if [ $pcmode = yes ]; then
 		if [ "${__git_printf_supports_v-}" != yes ]; then
```
