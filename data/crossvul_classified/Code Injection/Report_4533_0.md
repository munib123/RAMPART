# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 4533_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4533_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 24-64 of the vulnerable file.

import javax.xml.bind.annotation.adapters.XmlAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * Interface for an identifier.
 */
@XmlJavaTypeAdapter(Id.Adapter.class)
public interface Id {

  /**
   * Returns the local identifier of this {@link Id}. The local identifier is defined to be free of separator characters
   * that could potentially get into the way when creating file or directory names from the identifier.
   *
   * For example, given that the interface is implemented by a class representing CNRI handles, the identifier would
   * then look something like <code>10.3930/ETHZ/abcd</code>, whith <code>10.3930</code> being the handle prefix,
   * <code>ETH</code> the authority and <code>abcd</code> the local part. <code>toURI()</code> would then return
   * <code>10.3930-ETH-abcd</code> or any other suitable form.
   *
   * @return a path separator-free representation of the identifier
   */
  String compact();

  class Adapter extends XmlAdapter<IdImpl, Id> {
    public IdImpl marshal(Id id) throws Exception {
      if (id instanceof IdImpl) {
        return (IdImpl) id;
      } else {
        throw new IllegalStateException("an unknown ID is un use: " + id);
      }
    }

    public Id unmarshal(IdImpl id) throws Exception {
      return id;
    }
  }

  /**
   * Return a string representation of the identifier from which an object of type Id should
   * be reconstructable.
   */
  String toString();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,6 +41,7 @@
    *
    * @return a path separator-free representation of the identifier
    */
+  @Deprecated
   String compact();
 
   class Adapter extends XmlAdapter<IdImpl, Id> {
```
