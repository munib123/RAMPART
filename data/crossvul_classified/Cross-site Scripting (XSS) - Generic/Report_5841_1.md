# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in java
**Pair ID:** 5841_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5841_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```java
Lines 228-268 of the vulnerable file.

   * Please note: Please, use only getFavorites() OR getRecentUserInputs()!
   */
  protected abstract List<String> getRecentUserInputs();

  /**
   * Used for formatting the values.
   */
  protected abstract String formatValue(T value);

  /**
   * Used for formatting the labels if labelValue is set to true.
   * @return null at default (if not overload).
   */
  protected String formatLabel(final T value)
  {
    return null;
  }

  private class MyJsonBuilder extends JsonBuilder
  {
    @SuppressWarnings("unchecked")
    @Override
    protected String formatValue(final Object obj)
    {
      if (obj instanceof String) {
        return obj.toString();
      } else {
        return PFAutoCompleteBehavior.this.formatValue((T) obj);
      }
    }

    @SuppressWarnings("unchecked")
    @Override
    protected Object transform(final Object obj)
    {
      if (settings.isLabelValue() == true) {
        final Object[] oa = new Object[2];
        if (obj instanceof String) {
          oa[0] = obj;
          oa[1] = obj;
        } else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -245,6 +245,11 @@
 
   private class MyJsonBuilder extends JsonBuilder
   {
+    private MyJsonBuilder()
+    {
+      setEscapeHtml(true);
+    }
+
     @SuppressWarnings("unchecked")
     @Override
     protected String formatValue(final Object obj)
```
