# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 3399_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3399_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 371-411 of the vulnerable file.

			free (node->value);
			node->value = strdup ("");
		}
		if (node->flags & CN_BOOL) {
			bool b = is_true (value);
			node->i_value = (ut64) b? 1: 0;
			char *value = strdup (r_str_bool (b));
			if (value) {
				free (node->value);
				node->value = value;
			}
		} else {
			if (!value) {
				free (node->value);
				node->value = strdup ("");
				node->i_value = 0;
			} else {
				if (node->value == value) {
					goto beach;
				}
				free (node->value);
				node->value = strdup (value);
				if (IS_DIGIT (*value)) {
					if (strchr (value, '/')) {
						node->i_value = r_num_get (cfg->num, value);
					} else {
						node->i_value = r_num_math (cfg->num, value);
					}
				} else {
					node->i_value = 0;
				}
				node->flags |= CN_INT;
			}
		}
	} else { // Create a new RConfigNode
		oi = UT64_MAX;
		if (!cfg->lock) {
			node = r_config_node_new (name, value);
			if (node) {
				if (value && is_bool (value)) {
					node->flags |= CN_BOOL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -388,8 +388,9 @@
 				if (node->value == value) {
 					goto beach;
 				}
-				free (node->value);
+				char *tmp = node->value;
 				node->value = strdup (value);
+				free (tmp);
 				if (IS_DIGIT (*value)) {
 					if (strchr (value, '/')) {
 						node->i_value = r_num_get (cfg->num, value);
```
