# CrossVul Fix Pair: Improper Handling of Exceptional Conditions in cpp
**Pair ID:** 4096_0
**Vulnerability Class:** Improper Handling of Exceptional Conditions
**CWE:** CWE-755
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4096_0`)

## Vulnerability Information & PoC

## Description
Improper Handling of Exceptional Conditions - The product does not handle or incorrectly handles an exceptional condition.

## Vulnerable Code
```cpp
Lines 42-82 of the vulnerable file.

    va_start(args, fmt);
    vwritef(stream, fmt, size, args);
    va_end(args);
}

bool
ProtocolUtil::readf(synergy::IStream* stream, const char* fmt, ...)
{
    assert(stream != NULL);
    assert(fmt != NULL);
    LOG((CLOG_DEBUG2 "readf(%s)", fmt));

    bool result;
    va_list args;
    va_start(args, fmt);
    try {
        vreadf(stream, fmt, args);
        result = true;
    }
    catch (XIO&) {
        result = false;
    }
    va_end(args);
    return result;
}

void
ProtocolUtil::vwritef(synergy::IStream* stream,
                const char* fmt, UInt32 size, va_list args)
{
    assert(stream != NULL);
    assert(fmt != NULL);

    // done if nothing to write
    if (size == 0) {
        return;
    }

    // fill buffer
    UInt8* buffer = new UInt8[size];
    writef(buffer, fmt, args);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,6 +61,9 @@
     catch (XIO&) {
         result = false;
     }
+    catch (std::bad_alloc & exception) {
+        result = false;
+    }
     va_end(args);
     return result;
 }
@@ -216,7 +219,15 @@
                 // allocate a buffer to read the data
                 UInt8* sBuffer = buffer;
                 if (!useFixed) {
-                    sBuffer = new UInt8[len];
+                    try{
+                        sBuffer = new UInt8[len];
+                    }
+                    catch (std::bad_alloc & exception) {
+                        // Added try catch due to GHSA-chfm-333q-gfpp
+                        LOG((CLOG_ERR "ALLOC: Unable to allocate memory %d bytes", len));
+                        LOG((CLOG_DEBUG "bad_alloc detected: Do you have enough free memory?"));
+                        throw exception;
+                    }
                 }
 
                 // read the data
```
