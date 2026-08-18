# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in go
**Pair ID:** 73_3
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `73_3`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```go
Lines 202-234 of the vulnerable file.


// untar un-tarballs the contents of tr into destination.
func untar(tr *tar.Reader, destination string) error {
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		if err := untarFile(tr, header, destination); err != nil {
			return err
		}
	}
	return nil
}

// untarFile untars a single file from tr with header header into destination.
func untarFile(tr *tar.Reader, header *tar.Header, destination string) error {
	switch header.Typeflag {
	case tar.TypeDir:
		return mkdir(filepath.Join(destination, header.Name))
	case tar.TypeReg, tar.TypeRegA, tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		return writeNewFile(filepath.Join(destination, header.Name), tr, header.FileInfo().Mode())
	case tar.TypeSymlink:
		return writeNewSymbolicLink(filepath.Join(destination, header.Name), header.Linkname)
	case tar.TypeLink:
		return writeNewHardLink(filepath.Join(destination, header.Name), filepath.Join(destination, header.Linkname))
	default:
		return fmt.Errorf("%s: unknown type flag: %c", header.Name, header.Typeflag)
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -219,15 +219,22 @@
 
 // untarFile untars a single file from tr with header header into destination.
 func untarFile(tr *tar.Reader, header *tar.Header, destination string) error {
+	err := sanitizeExtractPath(header.Name, destination)
+	if err != nil {
+		return err
+	}
+
+	destpath := filepath.Join(destination, header.Name)
+
 	switch header.Typeflag {
 	case tar.TypeDir:
-		return mkdir(filepath.Join(destination, header.Name))
+		return mkdir(destpath)
 	case tar.TypeReg, tar.TypeRegA, tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
-		return writeNewFile(filepath.Join(destination, header.Name), tr, header.FileInfo().Mode())
+		return writeNewFile(destpath, tr, header.FileInfo().Mode())
 	case tar.TypeSymlink:
-		return writeNewSymbolicLink(filepath.Join(destination, header.Name), header.Linkname)
+		return writeNewSymbolicLink(destpath, header.Linkname)
 	case tar.TypeLink:
-		return writeNewHardLink(filepath.Join(destination, header.Name), filepath.Join(destination, header.Linkname))
+		return writeNewHardLink(destpath, filepath.Join(destination, header.Linkname))
 	default:
 		return fmt.Errorf("%s: unknown type flag: %c", header.Name, header.Typeflag)
 	}
```
