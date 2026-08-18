# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in go
**Pair ID:** 73_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `73_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```go
Lines 10-50 of the vulnerable file.

func main() {
	if len(os.Args) < 3 {
		fatal(usage)
	}

	cmd, filename := os.Args[1], os.Args[2]

	ff := archiver.MatchingFormat(filename)
	if ff == nil {
		fatalf("%s: Unsupported file extension", filename)
	}

	var err error
	switch cmd {
	case "make":
		if len(os.Args) < 4 {
			fatal(usage)
		}
		err = ff.Make(filename, os.Args[3:])
	case "open":
		dest := ""
		if len(os.Args) == 4 {
			dest = os.Args[3]
		} else if len(os.Args) > 4 {
			fatal(usage)
		}
		err = ff.Open(filename, dest)
	default:
		fatal(usage)
	}
	if err != nil {
		fatal(err)
	}
}

func fatal(v ...interface{}) {
	fmt.Fprintln(os.Stderr, v...)
	os.Exit(1)
}

func fatalf(s string, v ...interface{}) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,7 +27,10 @@
 		}
 		err = ff.Make(filename, os.Args[3:])
 	case "open":
-		dest := ""
+		dest, osErr := os.Getwd()
+		if osErr != nil {
+			fatal(err)
+		}
 		if len(os.Args) == 4 {
 			dest = os.Args[3]
 		} else if len(os.Args) > 4 {
```
