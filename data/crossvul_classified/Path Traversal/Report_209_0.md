# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in go
**Pair ID:** 209_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `209_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```go
Lines 361-401 of the vulnerable file.

		metaProto, imRoot, _, redir, err = fetchMeta(ctx, client, im.projectRoot)
		if err != nil {
			return nil, err
		}
		if *imRoot != *im {
			return nil, NotFoundError{Message: "project root mismatch."}
		}
	}

	// clonePath is the repo URL from import meta tag, with the "scheme://" prefix removed.
	// It should be used for cloning repositories.
	// repo is the repo URL from import meta tag, with the "scheme://" prefix removed, and
	// a possible ".vcs" suffix trimmed.
	i := strings.Index(im.repo, "://")
	if i < 0 {
		return nil, NotFoundError{Message: "bad repo URL: " + im.repo}
	}
	proto := im.repo[:i]
	clonePath := im.repo[i+len("://"):]
	repo := strings.TrimSuffix(clonePath, "."+im.vcs)
	dirName := importPath[len(im.projectRoot):]

	resolvedPath := repo + dirName
	dir, err := getStatic(ctx, client, resolvedPath, etag)
	if err == errNoMatch {
		resolvedPath = repo + "." + im.vcs + dirName
		match := map[string]string{
			"dir":        dirName,
			"importPath": importPath,
			"clonePath":  clonePath,
			"repo":       repo,
			"scheme":     proto,
			"vcs":        im.vcs,
		}
		dir, err = getVCSDirFn(ctx, client, match, etag)
	}
	if err != nil || dir == nil {
		return nil, err
	}

	dir.ImportPath = importPath
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -378,6 +378,9 @@
 	proto := im.repo[:i]
 	clonePath := im.repo[i+len("://"):]
 	repo := strings.TrimSuffix(clonePath, "."+im.vcs)
+	if !IsValidRemotePath(repo) {
+		return nil, fmt.Errorf("bad path from meta: %s", repo)
+	}
 	dirName := importPath[len(im.projectRoot):]
 
 	resolvedPath := repo + dirName
```
