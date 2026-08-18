# CrossVul Fix Pair: Uncontrolled Resource Consumption in go
**Pair ID:** 1923_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1923_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```go
Lines 507-547 of the vulnerable file.

						tm := time.Now()
						end = &tm
					}
					_ = pw.Write("extracting "+p.ID, progress.Status{
						Action:    "extract",
						Started:   &st.st,
						Completed: end,
					})
				}
			}
		}
	}()

	if len(mfst.Layers) == 0 {
		return nil, nil
	}

	layers := make([]xfer.DownloadDescriptor, 0, len(mfst.Layers))

	for i, desc := range mfst.Layers {
		ongoing.add(desc)
		layers = append(layers, &layerDescriptor{
			desc:    desc,
			diffID:  layer.DiffID(img.RootFS.DiffIDs[i]),
			fetcher: fetcher,
			ref:     p.src.Reference,
			is:      p.is,
		})
	}

	defer func() {
		<-progressDone
		for _, desc := range mfst.Layers {
			p.is.ContentStore.Delete(context.TODO(), desc.Digest)
		}
	}()

	r := image.NewRootFS()
	rootFS, release, err := p.is.DownloadManager.Download(ctx, *r, runtime.GOOS, layers, pkgprogress.ChanOutput(pchan))
	stopProgress()
	if err != nil {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -524,6 +524,9 @@
 	layers := make([]xfer.DownloadDescriptor, 0, len(mfst.Layers))
 
 	for i, desc := range mfst.Layers {
+		if err := desc.Digest.Validate(); err != nil {
+			return nil, errors.Wrap(err, "layer digest could not be validated")
+		}
 		ongoing.add(desc)
 		layers = append(layers, &layerDescriptor{
 			desc:    desc,
```
