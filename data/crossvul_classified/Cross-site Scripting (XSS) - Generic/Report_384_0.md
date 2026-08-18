# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in c
**Pair ID:** 384_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `384_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```c
Lines 661-701 of the vulnerable file.

		zfd.type = ZEND_HANDLE_FILENAME;
		zfd.filename = (char *) r->filename;
		zfd.free_filename = 0;
		zfd.opened_path = NULL;

		if (!parent_req) {
			php_execute_script(&zfd TSRMLS_CC);
		} else {
			zend_execute_scripts(ZEND_INCLUDE TSRMLS_CC, NULL, 1, &zfd);
		}

		apr_table_set(r->notes, "mod_php_memory_usage",
			apr_psprintf(ctx->r->pool, "%" APR_SIZE_T_FMT, zend_memory_peak_usage(1 TSRMLS_CC)));
	}

} zend_end_try();

	if (!parent_req) {
		php_apache_request_dtor(r TSRMLS_CC);
		ctx->request_processed = 1;
		bucket = apr_bucket_eos_create(r->connection->bucket_alloc);
		APR_BRIGADE_INSERT_TAIL(brigade, bucket);

		rv = ap_pass_brigade(r->output_filters, brigade);
		if (rv != APR_SUCCESS || r->connection->aborted) {
zend_first_try {
			php_handle_aborted_connection();
} zend_end_try();
		}
		apr_brigade_cleanup(brigade);
		apr_pool_cleanup_run(r->pool, (void *)&SG(server_context), php_server_context_cleanup);
	} else {
		ctx->r = parent_req;
	}

	return OK;
}

static void php_apache_child_init(apr_pool_t *pchild, server_rec *s)
{
	apr_pool_cleanup_register(pchild, NULL, php_apache_child_shutdown, apr_pool_cleanup_null);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -678,6 +678,7 @@
 	if (!parent_req) {
 		php_apache_request_dtor(r TSRMLS_CC);
 		ctx->request_processed = 1;
+		apr_brigade_cleanup(brigade);
 		bucket = apr_bucket_eos_create(r->connection->bucket_alloc);
 		APR_BRIGADE_INSERT_TAIL(brigade, bucket);
 
```
