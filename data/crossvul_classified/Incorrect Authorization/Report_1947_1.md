# CrossVul Fix Pair: Incorrect Authorization in java
**Pair ID:** 1947_1
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1947_1`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```java
Lines 33-73 of the vulnerable file.

import javax.persistence.JoinColumn;
import javax.persistence.Lob;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

/**
 * Entity object for storing search in persistence storage. Media package id is stored as primary key.
 */
@Entity(name = "SearchEntity")
@Table(name = "oc_search", indexes = {
    @Index(name = "IX_oc_search_series", columnList = ("series_id")),
    @Index(name = "IX_oc_search_organization", columnList = ("organization")) })
@NamedQueries({
    @NamedQuery(name = "Search.findAll", query = "SELECT s FROM SearchEntity s"),
    @NamedQuery(name = "Search.getCount", query = "SELECT COUNT(s) FROM SearchEntity s"),
    @NamedQuery(name = "Search.findById", query = "SELECT s FROM SearchEntity s WHERE s.mediaPackageId=:mediaPackageId"),
    @NamedQuery(name = "Search.findBySeriesId", query = "SELECT s FROM SearchEntity s WHERE s.seriesId=:seriesId"),
    @NamedQuery(name = "Search.getNoSeries", query = "SELECT s FROM SearchEntity s WHERE s.seriesId IS NULL")})
public class SearchEntity {

  /** media package id, primary key */
  @Id
  @Column(name = "id", length = 128)
  private String mediaPackageId;

  @Column(name = "series_id", length = 128)
  protected String seriesId;

  /** Organization id */
  @OneToOne(targetEntity = JpaOrganization.class)
  @JoinColumn(name = "organization", referencedColumnName = "id")
  protected JpaOrganization organization;

  /** The media package deleted */
  @Column(name = "deletion_date")
  @Temporal(TemporalType.TIMESTAMP)
  private Date deletionDate;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -50,7 +50,8 @@
     @NamedQuery(name = "Search.findAll", query = "SELECT s FROM SearchEntity s"),
     @NamedQuery(name = "Search.getCount", query = "SELECT COUNT(s) FROM SearchEntity s"),
     @NamedQuery(name = "Search.findById", query = "SELECT s FROM SearchEntity s WHERE s.mediaPackageId=:mediaPackageId"),
-    @NamedQuery(name = "Search.findBySeriesId", query = "SELECT s FROM SearchEntity s WHERE s.seriesId=:seriesId"),
+    @NamedQuery(name = "Search.findBySeriesId", query = "SELECT s FROM SearchEntity s WHERE s.seriesId=:seriesId and "
+        + "s.deletionDate is null"),
     @NamedQuery(name = "Search.getNoSeries", query = "SELECT s FROM SearchEntity s WHERE s.seriesId IS NULL")})
 public class SearchEntity {
 
```
