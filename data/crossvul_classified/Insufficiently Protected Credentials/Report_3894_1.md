# CrossVul Fix Pair: Insufficiently Protected Credentials in c
**Pair ID:** 3894_1
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3894_1`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```c
Lines 955-995 of the vulnerable file.

{
	return str[0] == '.' && (str[1] == '/' || str[1] == '\\');
}

/*
 * Like starts_with_dot_slash, this is a variant of submodule--helper's
 * helper of the same name with the twist that it accepts backslash as a
 * directory separator even on non-Windows platforms.
 */
static int starts_with_dot_dot_slash(const char *str)
{
	return str[0] == '.' && starts_with_dot_slash(str + 1);
}

static int submodule_url_is_relative(const char *url)
{
	return starts_with_dot_slash(url) || starts_with_dot_dot_slash(url);
}

/*
 * Check whether a transport is implemented by git-remote-curl.
 *
 * If it is, returns 1 and writes the URL that would be passed to
 * git-remote-curl to the "out" parameter.
 *
 * Otherwise, returns 0 and leaves "out" untouched.
 *
 * Examples:
 *   http::https://example.com/repo.git -> 1, https://example.com/repo.git
 *   https://example.com/repo.git -> 1, https://example.com/repo.git
 *   git://example.com/repo.git -> 0
 *
 * This is for use in checking for previously exploitable bugs that
 * required a submodule URL to be passed to git-remote-curl.
 */
static int url_to_curl_url(const char *url, const char **out)
{
	/*
	 * We don't need to check for case-aliases, "http.exe", and so
	 * on because in the default configuration, is_transport_allowed
	 * prevents URLs with those schemes from being cloned
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -972,6 +972,34 @@
 }
 
 /*
+ * Count directory components that a relative submodule URL should chop
+ * from the remote_url it is to be resolved against.
+ *
+ * In other words, this counts "../" components at the start of a
+ * submodule URL.
+ *
+ * Returns the number of directory components to chop and writes a
+ * pointer to the next character of url after all leading "./" and
+ * "../" components to out.
+ */
+static int count_leading_dotdots(const char *url, const char **out)
+{
+	int result = 0;
+	while (1) {
+		if (starts_with_dot_dot_slash(url)) {
+			result++;
+			url += strlen("../");
+			continue;
+		}
+		if (starts_with_dot_slash(url)) {
+			url += strlen("./");
+			continue;
+		}
+		*out = url;
+		return result;
+	}
+}
+/*
  * Check whether a transport is implemented by git-remote-curl.
  *
  * If it is, returns 1 and writes the URL that would be passed to
@@ -1018,14 +1046,29 @@
 		return -1;
 
 	if (submodule_url_is_relative(url)) {
+		char *decoded;
+		const char *next;
+		int has_nl;
+
 		/*
 		 * This could be appended to an http URL and url-decoded;
 		 * check for malicious characters.
 		 */
-		char *decoded = url_decode(url);
-		int has_nl = !!strchr(decoded, '\n');
+		decoded = url_decode(url);
+		has_nl = !!strchr(decoded, '\n');
+
 		free(decoded);
 		if (has_nl)
+			return -1;
+
+		/*
+		 * URLs which escape their root via "../" can overwrite
+		 * the host field and previous components, resolving to
+		 * URLs like https::example.com/submodule.git that were
+		 * susceptible to CVE-2020-11008.
+		 */
+		if (count_leading_dotdots(url, &next) > 0 &&
+		    *next == ':')
 			return -1;
 	}
 
```
