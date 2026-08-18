# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 4533_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4533_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 820-861 of the vulnerable file.


        /* Check if we got any media. Fail if not. */
        if (!hasMedia) {
          logger.warn("Rejected ingest without actual media.");
          return Response.serverError().status(Status.BAD_REQUEST).build();
        }

        /* Add episode mediapackage if metadata were send separately */
        if (dcc != null) {
          ByteArrayOutputStream out = new ByteArrayOutputStream();
          dcc.toXml(out, true);
          InputStream in = new ByteArrayInputStream(out.toByteArray());
          ingestService.addCatalog(in, "dublincore.xml", MediaPackageElements.EPISODE, mp);

          /* Check if we have metadata for the episode */
        } else if (episodeDCCatalogNumber == 0) {
          logger.warn("Rejected ingest without episode metadata. At least provide a title.");
          return Response.serverError().status(Status.BAD_REQUEST).build();
        }

        WorkflowInstance workflow = (wdID == null) ? ingestService.ingest(mp) : ingestService.ingest(mp, wdID,
                workflowProperties);
        return Response.ok(workflow).build();
      }
      return Response.serverError().status(Status.BAD_REQUEST).build();
    } catch (Exception e) {
      logger.warn(e.getMessage(), e);
      return Response.serverError().status(Status.INTERNAL_SERVER_ERROR).build();
    }
  }

  /**
   * Try updating the identifier of a mediapackage with the identifier from a episode DublinCore catalog.
   *
   * @param mp
   *          MediaPackage to modify
   * @param is
   *          InputStream containing the episode DublinCore catalog
   */
  private void updateMediaPackageID(MediaPackage mp, InputStream is) throws IOException {
    DublinCoreCatalog dc = DublinCores.read(is);
    EName en = new EName(DublinCore.TERMS_NS_URI, "identifier");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -837,11 +837,14 @@
           return Response.serverError().status(Status.BAD_REQUEST).build();
         }
 
-        WorkflowInstance workflow = (wdID == null) ? ingestService.ingest(mp) : ingestService.ingest(mp, wdID,
-                workflowProperties);
+        WorkflowInstance workflow = (wdID == null)
+            ? ingestService.ingest(mp)
+            : ingestService.ingest(mp, wdID, workflowProperties);
         return Response.ok(workflow).build();
       }
       return Response.serverError().status(Status.BAD_REQUEST).build();
+    } catch (IllegalArgumentException e) {
+      return Response.status(Status.BAD_REQUEST).entity(e.getMessage()).build();
     } catch (Exception e) {
       logger.warn(e.getMessage(), e);
       return Response.serverError().status(Status.INTERNAL_SERVER_ERROR).build();
```
