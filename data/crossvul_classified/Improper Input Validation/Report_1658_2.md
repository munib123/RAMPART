# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1658_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1658_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1998-2038 of the vulnerable file.

		stats_config(STATS_STATSDIR, ptree->stats_dir);

	/* NOTE:
	 * Calling filegen_get is brain dead. Doing a string
	 * comparison to find the relavant filegen structure is
	 * expensive.
	 *
	 * Through the parser, we already know which filegen is
	 * being specified. Hence, we should either store a
	 * pointer to the specified structure in the syntax tree
	 * or an index into a filegen array.
	 *
	 * Need to change the filegen code to reflect the above.
	 */

	/* Turn on the specified statistics */
	pfilegen_token = HEAD_PFIFO(ptree->stats_list);
	for (; pfilegen_token != NULL; pfilegen_token = pfilegen_token->link) {
		filegen_string = keyword(pfilegen_token->i);
		filegen = filegen_get(filegen_string);
		DPRINTF(4, ("enabling filegen for %s statistics '%s%s'\n",
			    filegen_string, filegen->prefix, 
			    filegen->basename));
		filegen->flag |= FGEN_FLAG_ENABLED;
	}

	/* Configure the statistics with the options */
	my_node = HEAD_PFIFO(ptree->filegen_opts);
	for (; my_node != NULL; my_node = my_node->link) {
		filegen_file = keyword(my_node->filegen_token);
		filegen = filegen_get(filegen_file);

		/* Initialize the filegen variables to their pre-configuration states */
		filegen_flag = filegen->flag;
		filegen_type = filegen->type;

		/* "filegen ... enabled" is the default (when filegen is used) */
		filegen_flag |= FGEN_FLAG_ENABLED;

		my_opts = HEAD_PFIFO(my_node->options);
		for (; my_opts != NULL; my_opts = my_opts->link) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2015,6 +2015,12 @@
 	for (; pfilegen_token != NULL; pfilegen_token = pfilegen_token->link) {
 		filegen_string = keyword(pfilegen_token->i);
 		filegen = filegen_get(filegen_string);
+		if (NULL == filegen) {
+			msyslog(LOG_ERR,
+				"stats %s unrecognized",
+				filegen_string);
+			continue;
+		}
 		DPRINTF(4, ("enabling filegen for %s statistics '%s%s'\n",
 			    filegen_string, filegen->prefix, 
 			    filegen->basename));
@@ -2026,6 +2032,12 @@
 	for (; my_node != NULL; my_node = my_node->link) {
 		filegen_file = keyword(my_node->filegen_token);
 		filegen = filegen_get(filegen_file);
+		if (NULL == filegen) {
+			msyslog(LOG_ERR,
+				"filegen category '%s' unrecognized",
+				filegen_file);
+			continue;
+		}
 
 		/* Initialize the filegen variables to their pre-configuration states */
 		filegen_flag = filegen->flag;
```
