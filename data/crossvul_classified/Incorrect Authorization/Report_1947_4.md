# CrossVul Fix Pair: Incorrect Authorization in java
**Pair ID:** 1947_4
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1947_4`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```java
Lines 256-297 of the vulnerable file.

    } catch (IOException e) {
      throw new SolrServerException(e);
    }
  }

  /**
   * Posts the media package to solr. Depending on what is referenced in the media package, the method might create one
   * or two entries: one for the episode and one for the series that the episode belongs to.
   *
   * This implementation of the search service removes all references to non "engage/download" media tracks
   *
   * @param sourceMediaPackage
   *          the media package to post
   * @param acl
   *          the access control list for this mediapackage
   * @param now
   *          current date
   * @throws SolrServerException
   *           if an errors occurs while talking to solr
   */
  public boolean add(MediaPackage sourceMediaPackage, AccessControlList acl, Date now) throws SolrServerException,
          UnauthorizedException {
    try {
      SolrInputDocument episodeDocument = createEpisodeInputDocument(sourceMediaPackage, acl);
      Schema.setOcModified(episodeDocument, now);

      SolrInputDocument seriesDocument = createSeriesInputDocument(sourceMediaPackage.getSeries(), acl);
      if (seriesDocument != null)
        Schema.enrich(episodeDocument, seriesDocument);

      // If neither an episode nor a series was contained, there is no point in trying to update
      if (episodeDocument == null && seriesDocument == null) {
        logger.warn("Neither episode nor series metadata found");
        return false;
      }

      // Post everything to the search index
      if (episodeDocument != null)
        solrServer.add(episodeDocument);
      if (seriesDocument != null)
        solrServer.add(seriesDocument);
      solrServer.commit();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -273,32 +273,47 @@
    * @throws SolrServerException
    *           if an errors occurs while talking to solr
    */
-  public boolean add(MediaPackage sourceMediaPackage, AccessControlList acl, Date now) throws SolrServerException,
-          UnauthorizedException {
+  public boolean add(MediaPackage sourceMediaPackage, AccessControlList acl, AccessControlList seriesAcl, Date now)
+      throws SolrServerException, UnauthorizedException {
     try {
       SolrInputDocument episodeDocument = createEpisodeInputDocument(sourceMediaPackage, acl);
       Schema.setOcModified(episodeDocument, now);
 
-      SolrInputDocument seriesDocument = createSeriesInputDocument(sourceMediaPackage.getSeries(), acl);
+      SolrInputDocument seriesDocument = createSeriesInputDocument(sourceMediaPackage.getSeries(), seriesAcl);
       if (seriesDocument != null)
         Schema.enrich(episodeDocument, seriesDocument);
 
-      // If neither an episode nor a series was contained, there is no point in trying to update
-      if (episodeDocument == null && seriesDocument == null) {
-        logger.warn("Neither episode nor series metadata found");
-        return false;
-      }
-
       // Post everything to the search index
-      if (episodeDocument != null)
-        solrServer.add(episodeDocument);
+      solrServer.add(episodeDocument);
       if (seriesDocument != null)
         solrServer.add(seriesDocument);
       solrServer.commit();
       return true;
     } catch (Exception e) {
-      logger.error("Unable to add mediapackage {} to index", sourceMediaPackage.getIdentifier());
-      throw new SolrServerException(e);
+      throw new SolrServerException(
+          String.format("Unable to add media package %s to index", sourceMediaPackage.getIdentifier()), e);
+    }
+  }
+
+  /**
+   * Posts a series to Solr. If the entry already exists, this will update the series.
+   *
+   * @param seriesId
+   *          the series to post
+   * @param acl
+   *          the access control list for this series
+   * @throws SolrServerException
+   *           if an errors occurs while talking to solr
+   */
+  public void addSeries(final String seriesId, final AccessControlList acl) throws SolrServerException {
+    try {
+      SolrInputDocument seriesDocument = createSeriesInputDocument(seriesId, acl);
+      if (seriesDocument != null) {
+        solrServer.add(seriesDocument);
+        solrServer.commit();
+      }
+    } catch (Exception e) {
+      throw new SolrServerException(String.format("Unable to add series %s to index", seriesId), e);
     }
   }
 
```
