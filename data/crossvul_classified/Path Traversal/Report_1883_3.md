# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in java
**Pair ID:** 1883_3
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1883_3`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```java
Lines 313-353 of the vulnerable file.


    @Test
    public void shouldEndpointBeSensitive() {
        assertThat(logViewEndpoint.isSensitive(), is(true));
    }

    @Test
    public void shouldReturnContextPath() {
        assertThat(logViewEndpoint.getPath(), is("/log"));
    }

    @Test
    public void shouldReturnNullEndpointType() {
        assertThat(logViewEndpoint.getEndpointType(), is(nullValue()));
    }

    @Test
    public void shouldNotAllowToListFileOutsideRoot() throws Exception {
        // given
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage(containsString("this String argument must not contain the substring [..]"));

        // when
        logViewEndpoint.view("../somefile", null, null, null);
    }

    @Test
    public void shouldViewFile() throws Exception {
        // given
        createFile("file.log", "abc", now);
        ByteArrayServletOutputStream outputStream = mockResponseOutputStream();

        // when
        logViewEndpoint.view("file.log", null, null, response);

        // then
        assertThat(new String(outputStream.toByteArray()), is("abc"));
    }

    @Test
    public void shouldTailViewOnlyLastLine() throws Exception {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -330,10 +330,20 @@
     public void shouldNotAllowToListFileOutsideRoot() throws Exception {
         // given
         expectedException.expect(IllegalArgumentException.class);
-        expectedException.expectMessage(containsString("this String argument must not contain the substring [..]"));
+        expectedException.expectMessage(containsString("may not be located outside base path"));
 
         // when
         logViewEndpoint.view("../somefile", null, null, null);
+    }
+
+    @Test
+    public void shouldNotAllowToListWithBaseOutsideRoot() throws Exception {
+        // given
+        expectedException.expect(IllegalArgumentException.class);
+        expectedException.expectMessage(containsString("may not be located outside base path"));
+
+        // when
+        logViewEndpoint.view("somefile", "../otherdir", null, null);
     }
 
     @Test
```
