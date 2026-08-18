# CrossVul Fix Pair: Improper Neutralization of Special Elements in Data Query Logic in cpp
**Pair ID:** 2652_0
**Vulnerability Class:** Improper Neutralization of Special Elements in Data Query Logic
**CWE:** CWE-943
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2652_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Data Query Logic - Depending on the capabilities of the query language, an attacker could inject additional logic into the query to: Modify the intended selection criteria, thus changing which data entities (e.

## Vulnerable Code
```cpp
Lines 1327-1367 of the vulnerable file.

/* When passing an argument to a shell script, empty string should be
 * represented as '' (two quote marks), otherwise shell won't be able to tell
 * that the parameter is empty */
std::string quote_empty(const std::string& input) {
	if (input.empty()) {
		return "''";
	} else {
		return input;
	}
}

std::string controller::bookmark(
		const std::string& url,
		const std::string& title,
		const std::string& description,
		const std::string& feed_title)
{
	std::string bookmark_cmd = cfg.get_configvalue("bookmark-cmd");
	bool is_interactive = cfg.get_configvalue_as_bool("bookmark-interactive");
	if (bookmark_cmd.length() > 0) {
		std::string cmdline = strprintf::fmt("%s '%s' %s %s %s",
		                                       bookmark_cmd,
		                                       utils::replace_all(url,"'", "%27"),
		                                       quote_empty(stfl::quote(title)),
		                                       quote_empty(stfl::quote(description)),
		                                       quote_empty(stfl::quote(feed_title)));

		LOG(level::DEBUG, "controller::bookmark: cmd = %s", cmdline);

		if (is_interactive) {
			v->push_empty_formaction();
			stfl::reset();
			utils::run_interactively(cmdline, "controller::bookmark");
			v->pop_current_formaction();
			return "";
		} else {
			char * my_argv[4];
			my_argv[0] = const_cast<char *>("/bin/sh");
			my_argv[1] = const_cast<char *>("-c");
			my_argv[2] = const_cast<char *>(cmdline.c_str());
			my_argv[3] = nullptr;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1344,12 +1344,12 @@
 	std::string bookmark_cmd = cfg.get_configvalue("bookmark-cmd");
 	bool is_interactive = cfg.get_configvalue_as_bool("bookmark-interactive");
 	if (bookmark_cmd.length() > 0) {
-		std::string cmdline = strprintf::fmt("%s '%s' %s %s %s",
+		std::string cmdline = strprintf::fmt("%s '%s' '%s' '%s' '%s'",
 		                                       bookmark_cmd,
 		                                       utils::replace_all(url,"'", "%27"),
-		                                       quote_empty(stfl::quote(title)),
-		                                       quote_empty(stfl::quote(description)),
-		                                       quote_empty(stfl::quote(feed_title)));
+		                                       utils::replace_all(title,"'", "%27"),
+		                                       utils::replace_all(description,"'", "%27"),
+		                                       utils::replace_all(feed_title,"'", "%27"));
 
 		LOG(level::DEBUG, "controller::bookmark: cmd = %s", cmdline);
 
```
