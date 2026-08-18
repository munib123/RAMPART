# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5174_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5174_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 499-539 of the vulnerable file.

		if (uref->report_id == HID_REPORT_ID_UNKNOWN) {
			field = hiddev_lookup_usage(hid, uref);
			if (field == NULL)
				goto inval;
		} else {
			rinfo.report_type = uref->report_type;
			rinfo.report_id = uref->report_id;
			if ((report = hiddev_lookup_report(hid, &rinfo)) == NULL)
				goto inval;

			if (uref->field_index >= report->maxfield)
				goto inval;

			field = report->field[uref->field_index];

			if (cmd == HIDIOCGCOLLECTIONINDEX) {
				if (uref->usage_index >= field->maxusage)
					goto inval;
			} else if (uref->usage_index >= field->report_count)
				goto inval;

			else if ((cmd == HIDIOCGUSAGES || cmd == HIDIOCSUSAGES) &&
				 (uref_multi->num_values > HID_MAX_MULTI_USAGES ||
				  uref->usage_index + uref_multi->num_values > field->report_count))
				goto inval;
		}

		switch (cmd) {
		case HIDIOCGUSAGE:
			uref->value = field->value[uref->usage_index];
			if (copy_to_user(user_arg, uref, sizeof(*uref)))
				goto fault;
			goto goodreturn;

		case HIDIOCSUSAGE:
			field->value[uref->usage_index] = uref->value;
			goto goodreturn;

		case HIDIOCGCOLLECTIONINDEX:
			i = field->usage[uref->usage_index].collection_index;
			kfree(uref_multi);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -516,12 +516,12 @@
 					goto inval;
 			} else if (uref->usage_index >= field->report_count)
 				goto inval;
-
-			else if ((cmd == HIDIOCGUSAGES || cmd == HIDIOCSUSAGES) &&
-				 (uref_multi->num_values > HID_MAX_MULTI_USAGES ||
-				  uref->usage_index + uref_multi->num_values > field->report_count))
-				goto inval;
-		}
+		}
+
+		if ((cmd == HIDIOCGUSAGES || cmd == HIDIOCSUSAGES) &&
+		    (uref_multi->num_values > HID_MAX_MULTI_USAGES ||
+		     uref->usage_index + uref_multi->num_values > field->report_count))
+			goto inval;
 
 		switch (cmd) {
 		case HIDIOCGUSAGE:
```
