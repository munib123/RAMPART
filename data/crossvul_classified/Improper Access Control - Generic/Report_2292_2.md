# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2292_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2292_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 49-89 of the vulnerable file.

APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ap_lua, AP_LUA, int, lua_open,
                                    (lua_State *L, apr_pool_t *p),
                                    (L, p), OK, DECLINED)

APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ap_lua, AP_LUA, int, lua_request,
                                    (lua_State *L, request_rec *r),
                                    (L, r), OK, DECLINED)
static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *lua_ssl_val = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_is_https) *lua_ssl_is_https = NULL;

module AP_MODULE_DECLARE_DATA lua_module;

#define AP_LUA_HOOK_FIRST (APR_HOOK_FIRST - 1)
#define AP_LUA_HOOK_LAST  (APR_HOOK_LAST  + 1)

typedef struct {
    const char *name;
    const char *file_name;
    const char *function_name;
    ap_lua_vm_spec *spec;
    apr_array_header_t *args;
} lua_authz_provider_spec;

apr_hash_t *lua_authz_providers;

typedef struct
{
    apr_bucket_brigade *tmpBucket;
    lua_State *L;
    ap_lua_vm_spec *spec;
    int broken;
} lua_filter_ctx;

apr_global_mutex_t *lua_ivm_mutex;
apr_shm_t *lua_ivm_shm;
char *lua_ivm_shmfile;

static apr_status_t shm_cleanup_wrapper(void *unused) {
    if (lua_ivm_shm) {
        return apr_shm_destroy(lua_ivm_shm);
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -66,8 +66,12 @@
     const char *file_name;
     const char *function_name;
     ap_lua_vm_spec *spec;
+} lua_authz_provider_spec;
+
+typedef struct {
+    lua_authz_provider_spec *spec;
     apr_array_header_t *args;
-} lua_authz_provider_spec;
+} lua_authz_provider_func;
 
 apr_hash_t *lua_authz_providers;
 
@@ -1692,6 +1696,7 @@
 {
     const char *provider_name;
     lua_authz_provider_spec *spec;
+    lua_authz_provider_func *func = apr_pcalloc(cmd->pool, sizeof(lua_authz_provider_func));
 
     apr_pool_userdata_get((void**)&provider_name, AUTHZ_PROVIDER_NAME_NOTE,
                           cmd->temp_pool);
@@ -1699,16 +1704,17 @@
 
     spec = apr_hash_get(lua_authz_providers, provider_name, APR_HASH_KEY_STRING);
     ap_assert(spec != NULL);
+    func->spec = spec;
 
     if (require_line && *require_line) {
         const char *arg;
-        spec->args = apr_array_make(cmd->pool, 2, sizeof(const char *));
+        func->args = apr_array_make(cmd->pool, 2, sizeof(const char *));
         while ((arg = ap_getword_conf(cmd->pool, &require_line)) && *arg) {
-            APR_ARRAY_PUSH(spec->args, const char *) = arg;
-        }
-    }
-
-    *parsed_require_line = spec;
+            APR_ARRAY_PUSH(func->args, const char *) = arg;
+        }
+    }
+
+    *parsed_require_line = func;
     return NULL;
 }
 
@@ -1722,7 +1728,8 @@
                                                          &lua_module);
     const ap_lua_dir_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                                      &lua_module);
-    const lua_authz_provider_spec *prov_spec = parsed_require_line;
+    const lua_authz_provider_func *prov_func = parsed_require_line;
+    const lua_authz_provider_spec *prov_spec = prov_func->spec;
     int result;
     int nargs = 0;
 
@@ -1744,19 +1751,19 @@
         return AUTHZ_GENERAL_ERROR;
     }
     ap_lua_run_lua_request(L, r);
-    if (prov_spec->args) {
+    if (prov_func->args) {
         int i;
-        if (!lua_checkstack(L, prov_spec->args->nelts)) {
+        if (!lua_checkstack(L, prov_func->args->nelts)) {
             ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02315)
                           "Error: authz provider %s: too many arguments", prov_spec->name);
             ap_lua_release_state(L, spec, r);
             return AUTHZ_GENERAL_ERROR;
         }
-        for (i = 0; i < prov_spec->args->nelts; i++) {
-            const char *arg = APR_ARRAY_IDX(prov_spec->args, i, const char *);
+        for (i = 0; i < prov_func->args->nelts; i++) {
+            const char *arg = APR_ARRAY_IDX(prov_func->args, i, const char *);
             lua_pushstring(L, arg);
         }
-        nargs = prov_spec->args->nelts;
+        nargs = prov_func->args->nelts;
     }
     if (lua_pcall(L, 1 + nargs, 1, 0)) {
         const char *err = lua_tostring(L, -1);
```
