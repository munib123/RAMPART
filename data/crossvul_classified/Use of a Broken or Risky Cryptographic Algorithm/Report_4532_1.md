# CrossVul Fix Pair: Use of a Broken or Risky Cryptographic Algorithm in java
**Pair ID:** 4532_1
**Vulnerability Class:** Use of a Broken or Risky Cryptographic Algorithm
**CWE:** CWE-327
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4532_1`)

## Vulnerability Information & PoC

## Description
Use of a Broken or Risky Cryptographic Algorithm - Cryptographic algorithms are the methods by which data is scrambled to prevent observation or influence by unauthorized actors.

## Vulnerable Code
```java
Lines 42-82 of the vulnerable file.

import javax.persistence.Lob;
import javax.persistence.ManyToMany;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.persistence.UniqueConstraint;

/**
 * JPA-annotated user object.
 */
@Entity
@Access(AccessType.FIELD)
@Table(name = "oc_user", uniqueConstraints = { @UniqueConstraint(columnNames = { "username", "organization" }) })
@NamedQueries({
  @NamedQuery(name = "User.findByQuery", query = "select u from JpaUser u where UPPER(u.username) like :query and u.organization.id = :org"),
  @NamedQuery(name = "User.findByIdAndOrg", query = "select u from JpaUser u where u.id=:id and u.organization.id = :org"),
  @NamedQuery(name = "User.findByUsername", query = "select u from JpaUser u where u.username=:u and u.organization.id = :org"),
  @NamedQuery(name = "User.findAll", query = "select u from JpaUser u where u.organization.id = :org"),
  @NamedQuery(name = "User.findAllByUserNames", query = "select u from JpaUser u where u.organization.id = :org AND u.username IN :names"),
  @NamedQuery(name = "User.countAll", query = "select COUNT(u) from JpaUser u where u.organization.id = :org") })
public class JpaUser implements User {

  @Id
  @GeneratedValue
  @Column(name = "id")
  private Long id;

  @Column(name = "username", length = 128)
  private String username;

  @Column(name = "name")
  private String name;

  @Column(name = "email")
  private String email;

  @Column(name = "manageable")
  private boolean manageable = true;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -59,6 +59,8 @@
   @NamedQuery(name = "User.findByIdAndOrg", query = "select u from JpaUser u where u.id=:id and u.organization.id = :org"),
   @NamedQuery(name = "User.findByUsername", query = "select u from JpaUser u where u.username=:u and u.organization.id = :org"),
   @NamedQuery(name = "User.findAll", query = "select u from JpaUser u where u.organization.id = :org"),
+  @NamedQuery(name = "User.findInsecureHash",
+              query = "select u from JpaUser u where length(u.password) = 32 and u.organization.id = :org"),
   @NamedQuery(name = "User.findAllByUserNames", query = "select u from JpaUser u where u.organization.id = :org AND u.username IN :names"),
   @NamedQuery(name = "User.countAll", query = "select COUNT(u) from JpaUser u where u.organization.id = :org") })
 public class JpaUser implements User {
```
