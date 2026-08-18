# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 596_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `596_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 683-725 of the vulnerable file.

}

static Array HHVM_METHOD(Memcache, getextendedstats,
                         const String& /*type*/ /* = null_string */,
                         int /*slabid*/ /* = 0 */, int /*limit*/ /* = 100 */) {
  auto data = Native::data<MemcacheData>(this_);
  memcached_return_t ret;
  memcached_stat_st *stats;

  stats = memcached_stat(&data->m_memcache, nullptr, &ret);
  if (ret != MEMCACHED_SUCCESS) {
    return Array();
  }

  int server_count = memcached_server_count(&data->m_memcache);

  Array return_val;

  for (int server_id = 0; server_id < server_count; server_id++) {
    memcached_stat_st *stat;
    char stats_key[30] = {0};
    size_t key_len;

    LMCD_SERVER_POSITION_INSTANCE_TYPE instance =
      memcached_server_instance_by_position(&data->m_memcache, server_id);
    const char *hostname = LMCD_SERVER_HOSTNAME(instance);
    in_port_t port = LMCD_SERVER_PORT(instance);

    stat = stats + server_id;

    Array server_stats = memcache_build_stats(&data->m_memcache, stat, &ret);
    if (ret != MEMCACHED_SUCCESS) {
      continue;
    }

    key_len = snprintf(stats_key, sizeof(stats_key), "%s:%d", hostname, port);

    return_val.set(String(stats_key, key_len, CopyString), server_stats);
  }

  free(stats);
  return return_val;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -700,9 +700,6 @@
 
   for (int server_id = 0; server_id < server_count; server_id++) {
     memcached_stat_st *stat;
-    char stats_key[30] = {0};
-    size_t key_len;
-
     LMCD_SERVER_POSITION_INSTANCE_TYPE instance =
       memcached_server_instance_by_position(&data->m_memcache, server_id);
     const char *hostname = LMCD_SERVER_HOSTNAME(instance);
@@ -715,9 +712,13 @@
       continue;
     }
 
-    key_len = snprintf(stats_key, sizeof(stats_key), "%s:%d", hostname, port);
-
-    return_val.set(String(stats_key, key_len, CopyString), server_stats);
+    auto const port_str = folly::to<std::string>(port);
+    auto const key_len = strlen(hostname) + 1 + port_str.length();
+    auto key = String(key_len, ReserveString);
+    key += hostname;
+    key += ":";
+    key += port_str;
+    return_val.set(key, server_stats);
   }
 
   free(stats);
```
