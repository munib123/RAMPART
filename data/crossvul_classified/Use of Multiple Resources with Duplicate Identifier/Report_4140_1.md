# CrossVul Fix Pair: Use of Multiple Resources with Duplicate Identifier in go
**Pair ID:** 4140_1
**Vulnerability Class:** Use of Multiple Resources with Duplicate Identifier
**CWE:** CWE-694
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4140_1`)

## Vulnerability Information & PoC

## Description
Use of Multiple Resources with Duplicate Identifier - If the product assumes that each resource has a unique identifier, the product could operate on the wrong resource if attackers can cause multiple resources to be associated with the same identifier.

## Vulnerable Code
```go
Lines 211-251 of the vulnerable file.

//
// This can leave the index in an unsorted state
func (i *IndexFile) Merge(f *IndexFile) {
	for _, cvs := range f.Entries {
		for _, cv := range cvs {
			if !i.Has(cv.Name, cv.Version) {
				e := i.Entries[cv.Name]
				i.Entries[cv.Name] = append(e, cv)
			}
		}
	}
}

// ChartVersion represents a chart entry in the IndexFile
type ChartVersion struct {
	*chart.Metadata
	URLs    []string  `json:"urls"`
	Created time.Time `json:"created,omitempty"`
	Removed bool      `json:"removed,omitempty"`
	Digest  string    `json:"digest,omitempty"`
}

// IndexDirectory reads a (flat) directory and generates an index.
//
// It indexes only charts that have been packaged (*.tgz).
//
// The index returned will be in an unsorted state
func IndexDirectory(dir, baseURL string) (*IndexFile, error) {
	archives, err := filepath.Glob(filepath.Join(dir, "*.tgz"))
	if err != nil {
		return nil, err
	}
	moreArchives, err := filepath.Glob(filepath.Join(dir, "**/*.tgz"))
	if err != nil {
		return nil, err
	}
	archives = append(archives, moreArchives...)

	index := NewIndexFile()
	for _, arch := range archives {
		fname, err := filepath.Rel(dir, arch)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -228,6 +228,23 @@
 	Created time.Time `json:"created,omitempty"`
 	Removed bool      `json:"removed,omitempty"`
 	Digest  string    `json:"digest,omitempty"`
+
+	// ChecksumDeprecated is deprecated in Helm 3, and therefore ignored. Helm 3 replaced
+	// this with Digest. However, with a strict YAML parser enabled, a field must be
+	// present on the struct for backwards compatibility.
+	ChecksumDeprecated string `json:"checksum,omitempty"`
+
+	// EngineDeprecated is deprecated in Helm 3, and therefore ignored. However, with a strict
+	// YAML parser enabled, this field must be present.
+	EngineDeprecated string `json:"engine,omitempty"`
+
+	// TillerVersionDeprecated is deprecated in Helm 3, and therefore ignored. However, with a strict
+	// YAML parser enabled, this field must be present.
+	TillerVersionDeprecated string `json:"tillerVersion,omitempty"`
+
+	// URLDeprecated is deprectaed in Helm 3, superseded by URLs. It is ignored. However,
+	// with a strict YAML parser enabled, this must be present on the struct.
+	URLDeprecated string `json:"url,omitempty"`
 }
 
 // IndexDirectory reads a (flat) directory and generates an index.
@@ -281,7 +298,7 @@
 // This will fail if API Version is not set (ErrNoAPIVersion) or if the unmarshal fails.
 func loadIndex(data []byte) (*IndexFile, error) {
 	i := &IndexFile{}
-	if err := yaml.Unmarshal(data, i); err != nil {
+	if err := yaml.UnmarshalStrict(data, i); err != nil {
 		return i, err
 	}
 	i.SortEntries()
```
