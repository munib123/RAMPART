# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in go
**Pair ID:** 1937_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1937_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```go
Lines 126-166 of the vulnerable file.

	return o.outputFormat.Write(out, &repoSearchWriter{data, o.maxColWidth})
}

func (o *searchRepoOptions) setupSearchedVersion() {
	debug("Original chart version: %q", o.version)

	if o.version != "" {
		return
	}

	if o.devel { // search for releases and prereleases (alpha, beta, and release candidate releases).
		debug("setting version to >0.0.0-0")
		o.version = ">0.0.0-0"
	} else { // search only for stable releases, prerelease versions will be skip
		debug("setting version to >0.0.0")
		o.version = ">0.0.0"
	}
}

func (o *searchRepoOptions) applyConstraint(res []*search.Result) ([]*search.Result, error) {
	if len(o.version) == 0 {
		return res, nil
	}

	constraint, err := semver.NewConstraint(o.version)
	if err != nil {
		return res, errors.Wrap(err, "an invalid version/constraint format")
	}

	data := res[:0]
	foundNames := map[string]bool{}
	appendSearchResults := func(res *search.Result) {
		data = append(data, res)
		if !o.versions {
			foundNames[res.Name] = true // If user hasn't requested all versions, only show the latest that matches
		}
	}
	for _, r := range res {
		if _, found := foundNames[r.Name]; found {
			continue
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -143,7 +143,7 @@
 }
 
 func (o *searchRepoOptions) applyConstraint(res []*search.Result) ([]*search.Result, error) {
-	if len(o.version) == 0 {
+	if o.version == "" {
 		return res, nil
 	}
 
@@ -154,26 +154,19 @@
 
 	data := res[:0]
 	foundNames := map[string]bool{}
-	appendSearchResults := func(res *search.Result) {
-		data = append(data, res)
-		if !o.versions {
-			foundNames[res.Name] = true // If user hasn't requested all versions, only show the latest that matches
-		}
-	}
 	for _, r := range res {
-		if _, found := foundNames[r.Name]; found {
+		// if not returning all versions and already have found a result,
+		// you're done!
+		if !o.versions && foundNames[r.Name] {
 			continue
 		}
 		v, err := semver.NewVersion(r.Chart.Version)
-
 		if err != nil {
-			// If the current version number check appears ErrSegmentStartsZero or ErrInvalidPrerelease error and not devel mode, ignore
-			if (err == semver.ErrSegmentStartsZero || err == semver.ErrInvalidPrerelease) && !o.devel {
-				continue
-			}
-			appendSearchResults(r)
-		} else if constraint.Check(v) {
-			appendSearchResults(r)
+			continue
+		}
+		if constraint.Check(v) {
+			data = append(data, r)
+			foundNames[r.Name] = true
 		}
 	}
 
@@ -194,6 +187,7 @@
 		ind, err := repo.LoadIndexFile(f)
 		if err != nil {
 			warning("Repo %q is corrupt or missing. Try 'helm repo update'.", n)
+			warning("%s", err)
 			continue
 		}
 
```
