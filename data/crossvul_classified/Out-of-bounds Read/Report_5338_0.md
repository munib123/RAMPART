# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5338_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5338_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1276-1316 of the vulnerable file.

	unsigned offset = field->report_offset;
	unsigned size = field->report_size;
	__s32 min = field->logical_minimum;
	__s32 max = field->logical_maximum;
	__s32 *value;

	value = kmalloc(sizeof(__s32) * count, GFP_ATOMIC);
	if (!value)
		return;

	for (n = 0; n < count; n++) {

		value[n] = min < 0 ?
			snto32(hid_field_extract(hid, data, offset + n * size,
			       size), size) :
			hid_field_extract(hid, data, offset + n * size, size);

		/* Ignore report if ErrorRollOver */
		if (!(field->flags & HID_MAIN_ITEM_VARIABLE) &&
		    value[n] >= min && value[n] <= max &&
		    field->usage[value[n] - min].hid == HID_UP_KEYBOARD + 1)
			goto exit;
	}

	for (n = 0; n < count; n++) {

		if (HID_MAIN_ITEM_VARIABLE & field->flags) {
			hid_process_event(hid, field, &field->usage[n], value[n], interrupt);
			continue;
		}

		if (field->value[n] >= min && field->value[n] <= max
			&& field->usage[field->value[n] - min].hid
			&& search(value, field->value[n], count))
				hid_process_event(hid, field, &field->usage[field->value[n] - min], 0, interrupt);

		if (value[n] >= min && value[n] <= max
			&& field->usage[value[n] - min].hid
			&& search(field->value, value[n], count))
				hid_process_event(hid, field, &field->usage[value[n] - min], 1, interrupt);
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1293,6 +1293,7 @@
 		/* Ignore report if ErrorRollOver */
 		if (!(field->flags & HID_MAIN_ITEM_VARIABLE) &&
 		    value[n] >= min && value[n] <= max &&
+		    value[n] - min < field->maxusage &&
 		    field->usage[value[n] - min].hid == HID_UP_KEYBOARD + 1)
 			goto exit;
 	}
@@ -1305,11 +1306,13 @@
 		}
 
 		if (field->value[n] >= min && field->value[n] <= max
+			&& field->value[n] - min < field->maxusage
 			&& field->usage[field->value[n] - min].hid
 			&& search(value, field->value[n], count))
 				hid_process_event(hid, field, &field->usage[field->value[n] - min], 0, interrupt);
 
 		if (value[n] >= min && value[n] <= max
+			&& value[n] - min < field->maxusage
 			&& field->usage[value[n] - min].hid
 			&& search(field->value, value[n], count))
 				hid_process_event(hid, field, &field->usage[value[n] - min], 1, interrupt);
```
