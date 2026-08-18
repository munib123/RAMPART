# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 851_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `851_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 76-116 of the vulnerable file.


ConcurrentTableSharedStore& apc_store_local(uid_t uid) {
  auto& cache = apc_store_local();
  auto iter = cache.find(uid);
  if (iter != cache.end()) return *(iter->second);
  auto table = new ConcurrentTableSharedStore;
  auto res = cache.insert(uid, table);
  if (!res.second) delete table;
  return *res.first->second;
}

ConcurrentTableSharedStore& apc_store() {
  if (UNLIKELY(!RuntimeOption::RepoAuthoritative &&
               RuntimeOption::EvalUnixServerQuarantineApc)) {
    if (auto uc = get_cli_ucred()) {
      return apc_store_local(uc->uid);
    }
  }
  void* vpStore = &s_apc_storage;
  return *static_cast<ConcurrentTableSharedStore*>(vpStore);
}

}

//////////////////////////////////////////////////////////////////////

void initialize_apc() {
  APCStats::Create();
  // Note: we never destruct APC, currently.
  void* vpStore = &s_apc_storage;
  new (vpStore) ConcurrentTableSharedStore;

  if (UNLIKELY(!RuntimeOption::RepoAuthoritative &&
               RuntimeOption::EvalUnixServerQuarantineApc)) {
    new (&s_user_apc_storage) UserAPCCache(10);
  }
}

//////////////////////////////////////////////////////////////////////

const StaticString
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -93,6 +93,11 @@
   }
   void* vpStore = &s_apc_storage;
   return *static_cast<ConcurrentTableSharedStore*>(vpStore);
+}
+
+bool isKeyInvalid(const String &key) {
+  // T39154441 - check if invalid chars exist
+  return key.find('\0') != -1;
 }
 
 }
@@ -307,9 +312,14 @@
         return Variant(false);
       }
       Variant v = iter.second();
-      apc_store().set(key.toString(), v, ttl);
-    }
-
+
+      auto const& strKey = key.toCStrRef();
+      if (isKeyInvalid(strKey)) {
+        throw_invalid_argument("apc key: (contains invalid characters)");
+        return Variant(false);
+      }
+      apc_store().set(strKey, v, ttl);
+    }
     return Variant(ArrayData::Create());
   }
 
@@ -318,6 +328,11 @@
     return Variant(false);
   }
   String strKey = key_or_array.toString();
+
+  if (isKeyInvalid(strKey)) {
+    throw_invalid_argument("apc key: (contains invalid characters)");
+    return Variant(false);
+  }
   apc_store().set(strKey, var, ttl);
   return Variant(true);
 }
@@ -330,6 +345,10 @@
                    const String& key,
                    const Variant& var) {
   if (!apcExtension::Enable) return false;
+  if (isKeyInvalid(key)) {
+    throw_invalid_argument("apc key: (contains invalid characters)");
+    return false;
+  }
   apc_store().setWithoutTTL(key, var);
   return true;
 }
@@ -353,8 +372,15 @@
         return false;
       }
       Variant v = iter.second();
-      if (!apc_store().add(key.toString(), v, ttl)) {
-        errors.add(key, -1);
+
+      auto const& strKey = key.toCStrRef();
+      if (isKeyInvalid(strKey)) {
+        throw_invalid_argument("apc key: (contains invalid characters)");
+        return false;
+      }
+
+      if (!apc_store().add(strKey, v, ttl)) {
+        errors.add(strKey, -1);
       }
     }
     return errors.toVariant();
@@ -365,6 +391,10 @@
     return false;
   }
   String strKey = key_or_array.toString();
+  if (isKeyInvalid(strKey)) {
+    throw_invalid_argument("apc key: (contains invalid characters)");
+    return false;
+  }
   return apc_store().add(strKey, var, ttl);
 }
 
```
