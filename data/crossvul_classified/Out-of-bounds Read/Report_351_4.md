# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 351_4
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `351_4`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1450-1490 of the vulnerable file.

	/* make sure it's a type we recognize */
	if ((object_record_type != COOLKEY_V1_OBJECT) && (object_record_type != COOLKEY_V0_OBJECT)) {
		return SC_ERROR_CORRUPTED_DATA;
	}


	/*
	 * now loop through all the attributes in the list. first find the start of the list
	 */
	attr = coolkey_attribute_start(obj, object_record_type, buf_len);
	if (attr == NULL) {
		return SC_ERROR_CORRUPTED_DATA;
	}
	buf_len -= (attr-obj);

	/* now get the count */
	attribute_count = coolkey_get_attribute_count(obj, object_record_type, buf_len);
	for (i=0; i < attribute_count; i++) {
		size_t record_len = coolkey_get_attribute_record_len(attr, object_record_type, buf_len);
		/* make sure we have the complete record */
		if (buf_len < record_len) {
				return SC_ERROR_CORRUPTED_DATA;
		}
		/* does the attribute match the one we are looking for */
		if (attr_type == coolkey_get_attribute_type(attr, object_record_type, record_len)) {
			/* yup, return it */
			return coolkey_get_attribute_data(attr, object_record_type, record_len, attribute);
		}
		/* go to the next attribute on the list */
		buf_len -= record_len;
		attr += record_len;
	}
	/* not find in attribute list, check the fixed attribute record */
	if (object_record_type == COOLKEY_V1_OBJECT) {
		unsigned long fixed_attributes = bebytes2ulong(object_head->fixed_attributes_values);

		return coolkey_get_attribute_data_fixed(attr_type, fixed_attributes, attribute);
	}
	return SC_ERROR_DATA_OBJECT_NOT_FOUND;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1467,7 +1467,7 @@
 	for (i=0; i < attribute_count; i++) {
 		size_t record_len = coolkey_get_attribute_record_len(attr, object_record_type, buf_len);
 		/* make sure we have the complete record */
-		if (buf_len < record_len) {
+		if (buf_len < record_len || record_len < 4) {
 				return SC_ERROR_CORRUPTED_DATA;
 		}
 		/* does the attribute match the one we are looking for */
```
