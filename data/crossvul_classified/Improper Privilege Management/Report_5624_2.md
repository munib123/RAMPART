# CrossVul Fix Pair: Improper Privilege Management in shell
**Pair ID:** 5624_2
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5624_2`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```bash
Lines 205-245 of the vulnerable file.

fi

# INSTALL AUTOJUMP
mkdir -p ${destdir}${prefix}share/autojump/ || exit 1
mkdir -p ${destdir}${prefix}bin/ || exit 1
mkdir -p ${destdir}${prefix}share/man/man1/ || exit 1
cp -v ./bin/icon.png ${destdir}${prefix}share/autojump/ || exit 1
cp -v ./bin/autojump ${destdir}${prefix}bin/ || exit 1
cp -v ./bin/autojump_argparse.py ${destdir}${prefix}bin/ || exit 1
cp -v ./docs/autojump.1 ${destdir}${prefix}share/man/man1/ || exit 1
mkdir -p ${destdir}etc/profile.d/ || exit 1
cp -v ./bin/autojump.sh ${destdir}etc/profile.d/ || exit 1
cp -v ./bin/autojump.bash ${destdir}etc/profile.d/ || exit 1
cp -v ./bin/autojump.zsh ${destdir}etc/profile.d/ || exit 1
mkdir -p ${destdir}${zshsharedir} || exit 1
# TODO: remove unused _j function (2013.02.01_1348, ting)
install -v -m 0755 ./bin/_j ${destdir}${zshsharedir} || exit 1

# MODIFY AUTOJUMP.SH FOR CUSTOM INSTALLS
if [[ -z ${local} ]] && [[ -z ${global} ]]; then
    sed -i "s:/destdir_.*_install:${destdir}etc/profile.d:g" ${destdir}etc/profile.d/autojump.sh
fi

# DISPLAY ADD MESSAGE
rc_file="~/.${shell}rc"
if [[ `uname` == "Darwin" ]] && [[ ${shell} == "bash" ]]; then
    rc_file="~/.bash_profile"
fi

aj_shell_file="${destdir}etc/profile.d/autojump.sh"
if [[ ${local} ]]; then
    aj_shell_file="~/.autojump/etc/profile.d/autojump.sh"
fi

echo
echo "Please add the line to ${rc_file} :"
echo
echo -e "[[ -s ${aj_shell_file} ]] && . ${aj_shell_file}"
echo
echo "You need to run 'source ${rc_file}' before you can start using autojump. To remove autojump, run './uninstall.sh'"
echo
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -222,7 +222,8 @@
 
 # MODIFY AUTOJUMP.SH FOR CUSTOM INSTALLS
 if [[ -z ${local} ]] && [[ -z ${global} ]]; then
-    sed -i "s:/destdir_.*_install:${destdir}etc/profile.d:g" ${destdir}etc/profile.d/autojump.sh
+    sed -i "s:#custom#\t::g" ${destdir}etc/profile.d/autojump.sh
+    sed -i "s:destdir_install\t:${destdir}etc/profile.d:g" ${destdir}etc/profile.d/autojump.sh
 fi
 
 # DISPLAY ADD MESSAGE
```
