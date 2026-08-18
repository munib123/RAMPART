# CrossVul Fix Pair: Uncontrolled Resource Consumption in go
**Pair ID:** 1923_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1923_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```go
Lines 511-551 of the vulnerable file.

		return "", "", err
	}

	rootFS := image.NewRootFS()

	// remove duplicate layers and check parent chain validity
	err = fixManifestLayers(verifiedManifest)
	if err != nil {
		return "", "", err
	}

	var descriptors []xfer.DownloadDescriptor

	// Image history converted to the new format
	var history []image.History

	// Note that the order of this loop is in the direction of bottom-most
	// to top-most, so that the downloads slice gets ordered correctly.
	for i := len(verifiedManifest.FSLayers) - 1; i >= 0; i-- {
		blobSum := verifiedManifest.FSLayers[i].BlobSum

		var throwAway struct {
			ThrowAway bool `json:"throwaway,omitempty"`
		}
		if err := json.Unmarshal([]byte(verifiedManifest.History[i].V1Compatibility), &throwAway); err != nil {
			return "", "", err
		}

		h, err := v1.HistoryFromConfig([]byte(verifiedManifest.History[i].V1Compatibility), throwAway.ThrowAway)
		if err != nil {
			return "", "", err
		}
		history = append(history, h)

		if throwAway.ThrowAway {
			continue
		}

		layerDescriptor := &v2LayerDescriptor{
			digest:            blobSum,
			repoInfo:          p.repoInfo,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -528,6 +528,9 @@
 	// to top-most, so that the downloads slice gets ordered correctly.
 	for i := len(verifiedManifest.FSLayers) - 1; i >= 0; i-- {
 		blobSum := verifiedManifest.FSLayers[i].BlobSum
+		if err = blobSum.Validate(); err != nil {
+			return "", "", errors.Wrapf(err, "could not validate layer digest %q", blobSum)
+		}
 
 		var throwAway struct {
 			ThrowAway bool `json:"throwaway,omitempty"`
@@ -626,6 +629,9 @@
 	// Note that the order of this loop is in the direction of bottom-most
 	// to top-most, so that the downloads slice gets ordered correctly.
 	for _, d := range layers {
+		if err := d.Digest.Validate(); err != nil {
+			return "", errors.Wrapf(err, "could not validate layer digest %q", d.Digest)
+		}
 		layerDescriptor := &v2LayerDescriptor{
 			digest:            d.Digest,
 			repo:              p.repo,
```
