# CrossVul Fix Pair: Incorrect Authorization in java
**Pair ID:** 1947_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1947_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```java
Lines 356-397 of the vulnerable file.

   *
   * @see org.opencastproject.search.api.SearchService#add(org.opencastproject.mediapackage.MediaPackage)
   */
  public Job add(MediaPackage mediaPackage) throws SearchException, MediaPackageException, IllegalArgumentException,
          UnauthorizedException, ServiceRegistryException {
    try {
      return serviceRegistry.createJob(JOB_TYPE, Operation.Add.toString(),
              Arrays.asList(MediaPackageParser.getAsXml(mediaPackage)), addJobLoad);
    } catch (ServiceRegistryException e) {
      throw new SearchException(e);
    }
  }

  /**
   * Immediately adds the mediapackage to the search index.
   *
   * @param mediaPackage
   *          the media package
   * @throws SearchException
   *           if the media package cannot be added to the search index
   * @throws MediaPackageException
   *           if the mediapckage is invalid
   * @throws IllegalArgumentException
   *           if the mediapackage is <code>null</code>
   * @throws UnauthorizedException
   *           if the user does not have the rights to add the mediapackage
   */
  public void addSynchronously(MediaPackage mediaPackage) throws SearchException, MediaPackageException,
          IllegalArgumentException, UnauthorizedException {
    if (mediaPackage == null) {
      throw new IllegalArgumentException("Unable to add a null mediapackage");
    }
    logger.debug("Attempting to add mediapackage {} to search index", mediaPackage.getIdentifier());
    AccessControlList acl = authorizationService.getActiveAcl(mediaPackage).getA();

    Date now = new Date();

    try {
      if (indexManager.add(mediaPackage, acl, now)) {
        logger.info("Added mediapackage `{}` to the search index, using ACL `{}`", mediaPackage, acl);
      } else {
        logger.warn("Failed to add mediapackage {} to the search index", mediaPackage.getIdentifier());
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -373,28 +373,32 @@
    *          the media package
    * @throws SearchException
    *           if the media package cannot be added to the search index
-   * @throws MediaPackageException
-   *           if the mediapckage is invalid
    * @throws IllegalArgumentException
    *           if the mediapackage is <code>null</code>
    * @throws UnauthorizedException
    *           if the user does not have the rights to add the mediapackage
    */
-  public void addSynchronously(MediaPackage mediaPackage) throws SearchException, MediaPackageException,
-          IllegalArgumentException, UnauthorizedException {
+  public void addSynchronously(MediaPackage mediaPackage)
+      throws SearchException, IllegalArgumentException, UnauthorizedException, NotFoundException,
+      SearchServiceDatabaseException {
     if (mediaPackage == null) {
       throw new IllegalArgumentException("Unable to add a null mediapackage");
     }
-    logger.debug("Attempting to add mediapackage {} to search index", mediaPackage.getIdentifier());
+    final String mediaPackageId = mediaPackage.getIdentifier().toString();
+    logger.debug("Attempting to add media package {} to search index", mediaPackageId);
     AccessControlList acl = authorizationService.getActiveAcl(mediaPackage).getA();
 
+    AccessControlList seriesAcl = persistence.getAccessControlLists(mediaPackage.getSeries(), mediaPackageId).stream()
+        .reduce(new AccessControlList(acl.getEntries()), AccessControlList::mergeActions);
+    logger.debug("Updating series with merged access control list: {}", seriesAcl);
+
     Date now = new Date();
 
     try {
-      if (indexManager.add(mediaPackage, acl, now)) {
-        logger.info("Added mediapackage `{}` to the search index, using ACL `{}`", mediaPackage, acl);
+      if (indexManager.add(mediaPackage, acl, seriesAcl, now)) {
+        logger.info("Added media package `{}` to the search index, using ACL `{}`", mediaPackageId, acl);
       } else {
-        logger.warn("Failed to add mediapackage {} to the search index", mediaPackage.getIdentifier());
+        logger.warn("Failed to add media package {} to the search index", mediaPackageId);
       }
     } catch (SolrServerException e) {
       throw new SearchException(e);
@@ -403,8 +407,8 @@
     try {
       persistence.storeMediaPackage(mediaPackage, acl, now);
     } catch (SearchServiceDatabaseException e) {
-      logger.error("Could not store media package to search database {}: {}", mediaPackage.getIdentifier(), e);
-      throw new SearchException(e);
+      throw new SearchException(
+          String.format("Could not store media package to search database %s", mediaPackageId), e);
     }
   }
 
@@ -429,13 +433,8 @@
    * @return <code>true</code> if the mediapackage was deleted
    * @throws SearchException
    *           if deletion failed
-   * @throws UnauthorizedException
-   *           if the user did not have access to the media package
-   * @throws NotFoundException
-   *           if the mediapackage did not exist
-   */
-  public boolean deleteSynchronously(String mediaPackageId) throws SearchException, UnauthorizedException,
-          NotFoundException {
+   */
+  public boolean deleteSynchronously(final String mediaPackageId) throws SearchException {
     SearchResult result;
     try {
       result = solrRequester.getForWrite(new SearchQuery().withId(mediaPackageId));
@@ -445,7 +444,8 @@
                 mediaPackageId);
         return false;
       }
-      logger.info("Removing mediapackage {} from search index", mediaPackageId);
+      final String seriesId = result.getItems()[0].getDcIsPartOf();
+      logger.info("Removing media package {} from search index", mediaPackageId);
 
       Date now = new Date();
       try {
@@ -460,8 +460,24 @@
         throw new SearchException(e);
       }
 
-      return indexManager.delete(mediaPackageId, now);
-    } catch (SolrServerException e) {
+      final boolean success = indexManager.delete(mediaPackageId, now);
+
+      // Update series
+      if (seriesId != null) {
+        if (persistence.getMediaPackages(seriesId).size() > 0) {
+          // Update series acl if there are still episodes in the series
+          final AccessControlList seriesAcl = persistence.getAccessControlLists(seriesId).stream()
+              .reduce(new AccessControlList(), AccessControlList::mergeActions);
+          indexManager.addSeries(seriesId, seriesAcl);
+
+        } else {
+          // Remove series if there are no episodes in the series any longer
+          indexManager.delete(seriesId, now);
+        }
+      }
+
+      return success;
+    } catch (SolrServerException | SearchServiceDatabaseException e) {
       logger.info("Could not delete media package with id {} from search index", mediaPackageId);
       throw new SearchException(e);
     }
```
