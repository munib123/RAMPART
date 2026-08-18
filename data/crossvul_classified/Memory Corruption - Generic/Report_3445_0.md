# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3445_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3445_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 639-679 of the vulnerable file.

{
	struct ias_object *obj;
	struct ias_attrib *attrib;
	int name_len;
	int attr_len;
	char name[IAS_MAX_CLASSNAME + 1];	/* 60 bytes */
	char attr[IAS_MAX_ATTRIBNAME + 1];	/* 60 bytes */
	__u8 *fp;
	int n;

	IRDA_DEBUG(4, "%s()\n", __func__);

	IRDA_ASSERT(self != NULL, return;);
	IRDA_ASSERT(self->magic == IAS_MAGIC, return;);
	IRDA_ASSERT(skb != NULL, return;);

	fp = skb->data;
	n = 1;

	name_len = fp[n++];
	memcpy(name, fp+n, name_len); n+=name_len;
	name[name_len] = '\0';

	attr_len = fp[n++];
	memcpy(attr, fp+n, attr_len); n+=attr_len;
	attr[attr_len] = '\0';

	IRDA_DEBUG(4, "LM-IAS: Looking up %s: %s\n", name, attr);
	obj = irias_find_object(name);

	if (obj == NULL) {
		IRDA_DEBUG(2, "LM-IAS: Object %s not found\n", name);
		iriap_getvaluebyclass_response(self, 0x1235, IAS_CLASS_UNKNOWN,
					       &irias_missing);
		return;
	}
	IRDA_DEBUG(4, "LM-IAS: found %s, id=%d\n", obj->name, obj->id);

	attrib = irias_find_attrib(obj, attr);
	if (attrib == NULL) {
		IRDA_DEBUG(2, "LM-IAS: Attribute %s not found\n", attr);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -656,10 +656,16 @@
 	n = 1;
 
 	name_len = fp[n++];
+
+	IRDA_ASSERT(name_len < IAS_MAX_CLASSNAME + 1, return;);
+
 	memcpy(name, fp+n, name_len); n+=name_len;
 	name[name_len] = '\0';
 
 	attr_len = fp[n++];
+
+	IRDA_ASSERT(attr_len < IAS_MAX_ATTRIBNAME + 1, return;);
+
 	memcpy(attr, fp+n, attr_len); n+=attr_len;
 	attr[attr_len] = '\0';
 
```
