# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in go
**Pair ID:** 1937_8
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1937_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```go
Lines 32-62 of the vulnerable file.

	// may contain a semantic version range.
	Version string `json:"version,omitempty"`
	// The URL to the repository.
	//
	// Appending `index.yaml` to this string should result in a URL that can be
	// used to fetch the repository index.
	Repository string `json:"repository"`
	// A yaml path that resolves to a boolean, used for enabling/disabling charts (e.g. subchart1.enabled )
	Condition string `json:"condition,omitempty"`
	// Tags can be used to group charts for enabling/disabling together
	Tags []string `json:"tags,omitempty"`
	// Enabled bool determines if chart should be loaded
	Enabled bool `json:"enabled,omitempty"`
	// ImportValues holds the mapping of source values to parent key to be imported. Each item can be a
	// string or pair of child/parent sublist items.
	ImportValues []interface{} `json:"import-values,omitempty"`
	// Alias usable alias to be used for the chart
	Alias string `json:"alias,omitempty"`
}

// Lock is a lock file for dependencies.
//
// It represents the state that the dependencies should be in.
type Lock struct {
	// Generated is the date the lock file was last generated.
	Generated time.Time `json:"generated"`
	// Digest is a hash of the dependencies in Chart.yaml.
	Digest string `json:"digest"`
	// Dependencies is the list of dependencies that this lock file has locked.
	Dependencies []*Dependency `json:"dependencies"`
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,6 +49,23 @@
 	Alias string `json:"alias,omitempty"`
 }
 
+// Validate checks for common problems with the dependency datastructure in
+// the chart. This check must be done at load time before the dependency's charts are
+// loaded.
+func (d *Dependency) Validate() error {
+	d.Name = sanitizeString(d.Name)
+	d.Version = sanitizeString(d.Version)
+	d.Repository = sanitizeString(d.Repository)
+	d.Condition = sanitizeString(d.Condition)
+	for i := range d.Tags {
+		d.Tags[i] = sanitizeString(d.Tags[i])
+	}
+	if d.Alias != "" && !aliasNameFormat.MatchString(d.Alias) {
+		return ValidationErrorf("dependency %q has disallowed characters in the alias", d.Name)
+	}
+	return nil
+}
+
 // Lock is a lock file for dependencies.
 //
 // It represents the state that the dependencies should be in.
```
