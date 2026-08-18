# CrossVul Fix Pair: Improper Input Validation in java
**Pair ID:** 195_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `195_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```java
Lines 122-162 of the vulnerable file.

            public boolean hasNext() {
              return it.hasNext();
            }
            @Override
            public String next() {
              return it.next().toString();
            }
          };
        }
        @Override
        public int size() {
          return headers.size();
        }
      };
    }
    return names;
  }

  @Override
  public MultiMap add(String name, String value) {
    headers.add(toLowerCase(name), value);
    return this;
  }

  @Override
  public MultiMap add(String name, Iterable<String> values) {
    headers.add(toLowerCase(name), values);
    return this;
  }

  @Override
  public MultiMap addAll(MultiMap headers) {
    for (Map.Entry<String, String> entry: headers.entries()) {
      add(entry.getKey(), entry.getValue());
    }
    return this;
  }

  @Override
  public MultiMap addAll(Map<String, String> map) {
    for (Map.Entry<String, String> entry: map.entrySet()) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -139,12 +139,14 @@
 
   @Override
   public MultiMap add(String name, String value) {
+    HttpUtils.validateHeader(name, value);
     headers.add(toLowerCase(name), value);
     return this;
   }
 
   @Override
   public MultiMap add(String name, Iterable<String> values) {
+    HttpUtils.validateHeader(name, values);
     headers.add(toLowerCase(name), values);
     return this;
   }
@@ -167,12 +169,14 @@
 
   @Override
   public MultiMap set(String name, String value) {
+    HttpUtils.validateHeader(name, value);
     headers.set(toLowerCase(name), value);
     return this;
   }
 
   @Override
   public MultiMap set(String name, Iterable<String> values) {
+    HttpUtils.validateHeader(name, values);
     headers.set(toLowerCase(name), values);
     return this;
   }
@@ -240,24 +244,28 @@
 
   @Override
   public MultiMap add(CharSequence name, CharSequence value) {
+    HttpUtils.validateHeader(name, value);
     headers.add(toLowerCase(name), value);
     return this;
   }
 
   @Override
   public MultiMap add(CharSequence name, Iterable<CharSequence> values) {
+    HttpUtils.validateHeader(name, values);
     headers.add(toLowerCase(name), values);
     return this;
   }
 
   @Override
   public MultiMap set(CharSequence name, CharSequence value) {
+    HttpUtils.validateHeader(name, value);
     headers.set(toLowerCase(name), value);
     return this;
   }
 
   @Override
   public MultiMap set(CharSequence name, Iterable<CharSequence> values) {
+    HttpUtils.validateHeader(name, values);
     headers.set(toLowerCase(name), values);
     return this;
   }
```
