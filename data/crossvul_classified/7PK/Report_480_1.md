# CrossVul Fix Pair: 7PK in c
**Pair ID:** 480_1
**Vulnerability Class:** 7PK
**CWE:** CWE-254
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `480_1`)

## Vulnerability Information & PoC

## Description
7PK - Security Features

## Vulnerable Code
```c
Lines 480-520 of the vulnerable file.

		config->listeners[config->listener_count-1].socket_domain = config->default_listener.socket_domain;
		config->listeners[config->listener_count-1].client_count = 0;
		config->listeners[config->listener_count-1].socks = NULL;
		config->listeners[config->listener_count-1].sock_count = 0;
		config->listeners[config->listener_count-1].client_count = 0;
		config->listeners[config->listener_count-1].use_username_as_clientid = config->default_listener.use_username_as_clientid;
#ifdef WITH_TLS
		config->listeners[config->listener_count-1].tls_version = config->default_listener.tls_version;
		config->listeners[config->listener_count-1].cafile = config->default_listener.cafile;
		config->listeners[config->listener_count-1].capath = config->default_listener.capath;
		config->listeners[config->listener_count-1].certfile = config->default_listener.certfile;
		config->listeners[config->listener_count-1].keyfile = config->default_listener.keyfile;
		config->listeners[config->listener_count-1].ciphers = config->default_listener.ciphers;
		config->listeners[config->listener_count-1].psk_hint = config->default_listener.psk_hint;
		config->listeners[config->listener_count-1].require_certificate = config->default_listener.require_certificate;
		config->listeners[config->listener_count-1].ssl_ctx = NULL;
		config->listeners[config->listener_count-1].crlfile = config->default_listener.crlfile;
		config->listeners[config->listener_count-1].use_identity_as_username = config->default_listener.use_identity_as_username;
		config->listeners[config->listener_count-1].use_subject_as_username = config->default_listener.use_subject_as_username;
#endif
		config->listeners[config->listener_count-1].security_options.password_file = config->default_listener.security_options.password_file;
		config->listeners[config->listener_count-1].security_options.psk_file = config->default_listener.security_options.psk_file;
		config->listeners[config->listener_count-1].security_options.auth_plugin_configs = config->default_listener.security_options.auth_plugin_configs;
		config->listeners[config->listener_count-1].security_options.auth_plugin_config_count = config->default_listener.security_options.auth_plugin_config_count;
		config->listeners[config->listener_count-1].security_options.allow_anonymous = config->default_listener.security_options.allow_anonymous;
	}

	/* Default to drop to mosquitto user if we are privileged and no user specified. */
	if(!config->user){
		config->user = "mosquitto";
	}
	if(db->verbose){
		config->log_type = INT_MAX;
	}
	return config__check(config);
}

void config__copy(struct mosquitto__config *src, struct mosquitto__config *dest)
{
	mosquitto__free(dest->security_options.acl_file);
	dest->security_options.acl_file = src->security_options.acl_file;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -497,6 +497,7 @@
 		config->listeners[config->listener_count-1].use_identity_as_username = config->default_listener.use_identity_as_username;
 		config->listeners[config->listener_count-1].use_subject_as_username = config->default_listener.use_subject_as_username;
 #endif
+		config->listeners[config->listener_count-1].security_options.acl_file = config->default_listener.security_options.acl_file;
 		config->listeners[config->listener_count-1].security_options.password_file = config->default_listener.security_options.password_file;
 		config->listeners[config->listener_count-1].security_options.psk_file = config->default_listener.security_options.psk_file;
 		config->listeners[config->listener_count-1].security_options.auth_plugin_configs = config->default_listener.security_options.auth_plugin_configs;
```
