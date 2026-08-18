# CrossVul Fix Pair: Out-of-bounds Write in shell
**Pair ID:** 3411_4
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3411_4`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```bash
Lines 38-78 of the vulnerable file.

}

RebuildJava() {
	Rebuild shlr/java
	Rebuild libr/asm
	Rebuild libr/bin
	Rebuild libr/core
}

RebuildCapstone() {
	Rebuild shlr/capstone
	Rebuild libr/asm
	Rebuild libr/anal
}

RebuildSdb() {
	Rebuild shlr/sdb
	Rebuild libr/util
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
bin)    RebuildBin ; ;;
gdb)    RebuildGdb ; ;;
sdb)    RebuildSdb ; ;;
spp)    RebuildSpp ; ;;
bin)    RebuildBin ; ;;
java)   RebuildJava ; ;;
iosdbg) RebuildIOSDebug ; ;;
capstone|cs) RebuildCapstone ; ;;
*)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -55,6 +55,11 @@
 	Rebuild libr/util
 }
 
+RebuildFs() {
+	Rebuild shlr/grub
+	Rebuild libr/fs
+}
+
 RebuildBin() {
 	Rebuild libr/bin
 	Rebuild libr/core
@@ -67,6 +72,7 @@
 }
 
 case "$1" in
+fs)     RebuildFs; ;;
 bin)    RebuildBin ; ;;
 gdb)    RebuildGdb ; ;;
 sdb)    RebuildSdb ; ;;
```
