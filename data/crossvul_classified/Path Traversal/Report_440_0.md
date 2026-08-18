# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in c
**Pair ID:** 440_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `440_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```c
Lines 164-204 of the vulnerable file.

	mod_alias_patch_connection(srv, con, p);

	/* not to include the tailing slash */
	basedir_len = buffer_string_length(con->physical.basedir);
	if ('/' == con->physical.basedir->ptr[basedir_len-1]) --basedir_len;
	uri_len = buffer_string_length(con->physical.path) - basedir_len;
	uri_ptr = con->physical.path->ptr + basedir_len;

	for (k = 0; k < p->conf.alias->used; k++) {
		data_string *ds = (data_string *)p->conf.alias->data[k];
		int alias_len = buffer_string_length(ds->key);

		if (alias_len > uri_len) continue;
		if (buffer_is_empty(ds->key)) continue;

		if (0 == (con->conf.force_lowercase_filenames ?
					strncasecmp(uri_ptr, ds->key->ptr, alias_len) :
					strncmp(uri_ptr, ds->key->ptr, alias_len))) {
			/* matched */

			buffer_copy_buffer(con->physical.basedir, ds->value);
			buffer_copy_buffer(srv->tmp_buf, ds->value);
			buffer_append_string(srv->tmp_buf, uri_ptr + alias_len);
			buffer_copy_buffer(con->physical.path, srv->tmp_buf);

			return HANDLER_GO_ON;
		}
	}

	/* not found */
	return HANDLER_GO_ON;
}

/* this function is called at dlopen() time and inits the callbacks */

int mod_alias_plugin_init(plugin *p);
int mod_alias_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("alias");

	p->init           = mod_alias_init;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -181,6 +181,21 @@
 					strncmp(uri_ptr, ds->key->ptr, alias_len))) {
 			/* matched */
 
+			/* check for path traversal in url-path following alias if key
+			 * does not end in slash, but replacement value ends in slash */
+			if (uri_ptr[alias_len] == '.') {
+				char *s = uri_ptr + alias_len + 1;
+				if (*s == '.') ++s;
+				if (*s == '/' || *s == '\0') {
+					size_t vlen = buffer_string_length(ds->value);
+					if (0 != alias_len && ds->key->ptr[alias_len-1] != '/'
+					    && 0 != vlen && ds->value->ptr[vlen-1] == '/') {
+						con->http_status = 403;
+						return HANDLER_FINISHED;
+					}
+				}
+			}
+
 			buffer_copy_buffer(con->physical.basedir, ds->value);
 			buffer_copy_buffer(srv->tmp_buf, ds->value);
 			buffer_append_string(srv->tmp_buf, uri_ptr + alias_len);
```
