# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5608_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5608_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 578-618 of the vulnerable file.

    apr_hash_t          *rule_id_htab;

    /* Hash */
    apr_array_header_t  *hash_method;
    const char *crypto_key;
    int                 crypto_key_len;
    const char          *crypto_param_name;
    int                 hash_is_enabled;
    int                 hash_enforcement;
    int                 crypto_key_add;
    int                 crypto_hash_href_rx;
    int                 crypto_hash_faction_rx;
    int                 crypto_hash_location_rx;
    int                 crypto_hash_iframesrc_rx;
    int                 crypto_hash_framesrc_rx;
    int                 crypto_hash_href_pm;
    int                 crypto_hash_faction_pm;
    int                 crypto_hash_location_pm;
    int                 crypto_hash_iframesrc_pm;
    int                 crypto_hash_framesrc_pm;
};

struct error_message_t {
    const char          *file;
    int                  line;
    int                  level;
    apr_status_t         status;
    const char          *message;
};

struct msc_engine {
    apr_pool_t              *mp;
    apr_global_mutex_t      *auditlog_lock;
    apr_global_mutex_t      *geo_lock;
    msre_engine             *msre;
    unsigned int             processing_mode;
};

struct msc_data_chunk {
    char                    *data;
    apr_size_t               length;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -595,6 +595,9 @@
     int                 crypto_hash_location_pm;
     int                 crypto_hash_iframesrc_pm;
     int                 crypto_hash_framesrc_pm;
+
+    /* xml */
+    int                 xml_external_entity;
 };
 
 struct error_message_t {
```
