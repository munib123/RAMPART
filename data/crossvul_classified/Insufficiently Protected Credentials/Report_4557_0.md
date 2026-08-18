# CrossVul Fix Pair: Insufficiently Protected Credentials in c
**Pair ID:** 4557_0
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4557_0`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```c
Lines 177-217 of the vulnerable file.

		} else if (!strcmp(key, "url")) {
			credential_from_url(c, value);
		} else if (!strcmp(key, "quit")) {
			c->quit = !!git_config_bool("quit", value);
		}
		/*
		 * Ignore other lines; we don't know what they mean, but
		 * this future-proofs us when later versions of git do
		 * learn new lines, and the helpers are updated to match.
		 */
	}

	strbuf_release(&line);
	return 0;
}

static void credential_write_item(FILE *fp, const char *key, const char *value)
{
	if (!value)
		return;
	fprintf(fp, "%s=%s\n", key, value);
}

void credential_write(const struct credential *c, FILE *fp)
{
	credential_write_item(fp, "protocol", c->protocol);
	credential_write_item(fp, "host", c->host);
	credential_write_item(fp, "path", c->path);
	credential_write_item(fp, "username", c->username);
	credential_write_item(fp, "password", c->password);
}

static int run_credential_helper(struct credential *c,
				 const char *cmd,
				 int want_output)
{
	struct child_process helper = CHILD_PROCESS_INIT;
	const char *argv[] = { NULL, NULL };
	FILE *fp;

	argv[0] = cmd;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -194,6 +194,8 @@
 {
 	if (!value)
 		return;
+	if (strchr(value, '\n'))
+		die("credential value for %s contains newline", key);
 	fprintf(fp, "%s=%s\n", key, value);
 }
 
```
