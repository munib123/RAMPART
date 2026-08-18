# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5658_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5658_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 881-921 of the vulnerable file.

				    "empty quoted string not permitted");
				return -1;
			}
			if (*p != '\0' && strspn(p, ws) == 0) {
				snprintf(msg, msglen, "quoted string not"
				    " followed by white space");
				return -1;
			}
		} else {
			fields[i] = p;
			p += strcspn(p, ws);
			if (*p != '\0')
				*p++ = '\0';
		}
		i++;
	}
	return i;
}

int
rad_get_vendor_attr(u_int32_t *vendor, const void **data, size_t *len)
{
	struct vendor_attribute *attr;

	attr = (struct vendor_attribute *)*data;
	*vendor = ntohl(attr->vendor_value);
	*data = attr->attrib_data;
	*len = attr->attrib_len - 2;

	return (attr->attrib_type);
}

int
rad_put_vendor_addr(struct rad_handle *h, int vendor, int type,
    struct in_addr addr)
{
	return (rad_put_vendor_attr(h, vendor, type, &addr.s_addr,
	    sizeof addr.s_addr));
}

int
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -898,14 +898,23 @@
 }
 
 int
-rad_get_vendor_attr(u_int32_t *vendor, const void **data, size_t *len)
+rad_get_vendor_attr(u_int32_t *vendor, unsigned char *type, const void **data, size_t *len, const void *raw, size_t raw_len)
 {
 	struct vendor_attribute *attr;
 
-	attr = (struct vendor_attribute *)*data;
+	if (raw_len < sizeof(struct vendor_attribute)) {
+		return -1;
+	}
+
+	attr = (struct vendor_attribute *) raw;
 	*vendor = ntohl(attr->vendor_value);
+	*type = attr->attrib_type;
 	*data = attr->attrib_data;
 	*len = attr->attrib_len - 2;
+
+	if ((attr->attrib_len + 4) > raw_len) {
+		return -1;
+	}
 
 	return (attr->attrib_type);
 }
```
