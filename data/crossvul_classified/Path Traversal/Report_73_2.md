# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in go
**Pair ID:** 73_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `73_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```go
Lines 55-95 of the vulnerable file.

func (rarFormat) Make(rarPath string, filePaths []string) error {
	return fmt.Errorf("make %s: RAR not implemented (proprietary format)", rarPath)
}

// Read extracts the RAR file read from input and puts the contents
// into destination.
func (rarFormat) Read(input io.Reader, destination string) error {
	rr, err := rardecode.NewReader(input, "")
	if err != nil {
		return fmt.Errorf("read: failed to create reader: %v", err)
	}

	for {
		header, err := rr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		if header.IsDir {
			err = mkdir(filepath.Join(destination, header.Name))
			if err != nil {
				return err
			}
			continue
		}

		// if files come before their containing folders, then we must
		// create their folders before writing the file
		err = mkdir(filepath.Dir(filepath.Join(destination, header.Name)))
		if err != nil {
			return err
		}

		err = writeNewFile(filepath.Join(destination, header.Name), rr, header.Mode())
		if err != nil {
			return err
		}
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -72,8 +72,15 @@
 			return err
 		}
 
+		err = sanitizeExtractPath(header.Name, destination)
+		if err != nil {
+			return err
+		}
+
+		destpath := filepath.Join(destination, header.Name)
+
 		if header.IsDir {
-			err = mkdir(filepath.Join(destination, header.Name))
+			err = mkdir(destpath)
 			if err != nil {
 				return err
 			}
@@ -82,12 +89,12 @@
 
 		// if files come before their containing folders, then we must
 		// create their folders before writing the file
-		err = mkdir(filepath.Dir(filepath.Join(destination, header.Name)))
+		err = mkdir(filepath.Dir(destpath))
 		if err != nil {
 			return err
 		}
 
-		err = writeNewFile(filepath.Join(destination, header.Name), rr, header.Mode())
+		err = writeNewFile(destpath, rr, header.Mode())
 		if err != nil {
 			return err
 		}
```
