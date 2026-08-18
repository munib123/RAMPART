# CrossVul Fix Pair: Data Processing Errors in java
**Pair ID:** 4951_1
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4951_1`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```java
Lines 41-61 of the vulnerable file.

        origInterpreter.eval("myNull = null;");
        Assert.assertNull(origInterpreter.eval("myNull"));
        final Interpreter deserInterpreter = TestUtil.serDeser(origInterpreter);
        Assert.assertNull(deserInterpreter.eval("myNull"));
    }


    /**
     * Tests that Primitive.NULL is correctly serialized/deserialized
     *
     * @throws Exception in case of failure
     */
    @Test
    public void testSpecialNullSerialization() throws Exception {
        final Interpreter originalInterpreter = new Interpreter();
        originalInterpreter.eval("myNull = null;");
        Assert.assertTrue((Boolean) originalInterpreter.eval("myNull == null"));
        final Interpreter deserInterpreter = TestUtil.serDeser(originalInterpreter);
        Assert.assertTrue((Boolean) deserInterpreter.eval("myNull == null"));
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,4 +58,20 @@
         final Interpreter deserInterpreter = TestUtil.serDeser(originalInterpreter);
         Assert.assertTrue((Boolean) deserInterpreter.eval("myNull == null"));
     }
+
+
+    /**
+     * Tests that a declared method can be serialized (but not exploited)
+     *
+     * @throws Exception in case of failure
+     */
+    @Test
+    public void testMethodSerialization() throws Exception {
+        final Interpreter origInterpreter = new Interpreter();
+        origInterpreter.eval("int method() { return 1337; }");
+        Assert.assertEquals(1337, origInterpreter.eval("method()"));
+        final Interpreter deserInterpreter = TestUtil.serDeser(origInterpreter);
+        Assert.assertEquals(1337, deserInterpreter.eval("method()"));
+    }
+
 }
```
