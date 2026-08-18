# CrossVul Fix Pair: Creation of Temporary File in Directory with Insecure Permissions in java
**Pair ID:** 1927_7
**Vulnerability Class:** Creation of Temporary File in Directory with Insecure Permissions
**CWE:** CWE-379
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1927_7`)

## Vulnerability Information & PoC

## Description
Creation of Temporary File in Directory with Insecure Permissions - On some operating systems, the fact that the temporary file exists may be apparent to any user with sufficient privileges to access that directory.

## Vulnerable Code
```java
Lines 160-200 of the vulnerable file.

                        url = ClassLoader.getSystemResource(fileName);
                    } else {
                        url = loader.getResource(fileName);
                    }
                    if (url == null) {
                        FileNotFoundException fnf = new FileNotFoundException(fileName);
                        ThrowableUtil.addSuppressedAndClear(fnf, suppressed);
                        throw fnf;
                    }
                } else {
                    FileNotFoundException fnf = new FileNotFoundException(path);
                    ThrowableUtil.addSuppressedAndClear(fnf, suppressed);
                    throw fnf;
                }
            }

            int index = libname.lastIndexOf('.');
            String prefix = libname.substring(0, index);
            String suffix = libname.substring(index);

            tmpFile = File.createTempFile(prefix, suffix, WORKDIR);
            in = url.openStream();
            out = new FileOutputStream(tmpFile);

            if (shouldShadedLibraryIdBePatched(packagePrefix)) {
                patchShadedLibraryId(in, out, originalName, name);
            } else {
                byte[] buffer = new byte[8192];
                int length;
                while ((length = in.read(buffer)) > 0) {
                    out.write(buffer, 0, length);
                }
            }

            out.flush();

            // Close the output stream before loading the unpacked library,
            // because otherwise Windows will refuse to load it when it's in use by other process.
            closeQuietly(out);
            out = null;
            loadLibrary(loader, tmpFile.getPath(), true);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -177,7 +177,7 @@
             String prefix = libname.substring(0, index);
             String suffix = libname.substring(index);
 
-            tmpFile = File.createTempFile(prefix, suffix, WORKDIR);
+            tmpFile = PlatformDependent.createTempFile(prefix, suffix, WORKDIR);
             in = url.openStream();
             out = new FileOutputStream(tmpFile);
 
```
