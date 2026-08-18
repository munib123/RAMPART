# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in shell
**Pair ID:** 3407_4
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3407_4`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```bash
Lines 55-87 of the vulnerable file.

	Rebuild libr/util
}

RebuildFs() {
	Rebuild shlr/grub
	Rebuild libr/fs
}

RebuildBin() {
	Rebuild libr/bin
	Rebuild libr/core
}

RebuildGdb() {
	Rebuild shlr/gdb
	Rebuild libr/io
	Rebuild libr/debug
}

case "$1" in
fs)     RebuildFs; ;;
bin)    RebuildBin ; ;;
gdb)    RebuildGdb ; ;;
sdb)    RebuildSdb ; ;;
spp)    RebuildSpp ; ;;
bin)    RebuildBin ; ;;
java)   RebuildJava ; ;;
iosdbg) RebuildIOSDebug ; ;;
capstone|cs) RebuildCapstone ; ;;
*)
	echo "Usage: sys/rebuild.sh [gdb|java|capstone|sdb|iosdbg|cs|sdb|bin]"
	;;
esac
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -72,7 +72,7 @@
 }
 
 case "$1" in
-fs)     RebuildFs; ;;
+grub|fs)RebuildFs; ;;
 bin)    RebuildBin ; ;;
 gdb)    RebuildGdb ; ;;
 sdb)    RebuildSdb ; ;;
```
