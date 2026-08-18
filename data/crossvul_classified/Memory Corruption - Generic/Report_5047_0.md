# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5047_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5047_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 760-800 of the vulnerable file.

		{
			s->append(s, "&amp;", 5);
		}
		else if (c == '<')
		{
			s->append(s, "&lt;", 4);
		}
		else if (c == '>')
		{
			s->append(s, "&gt;", 4);
		}
		else if (c == '"')
		{
			s->append(s, "&quot;", 6);
		}
		else
		{
			s->append_char(s, c);
		}
	}

	memcpy(outbuffer, s->str, XMLRPC_BUFSIZE);
}

static void xmlrpc_append_char_encode(mowgli_string_t *s, const char *s1)
{
	long unsigned int i;
	unsigned char c;
	char buf2[15];

	if ((!(s1) || (*(s1) == '\0')))
	{
		return;
	}

	for (i = 0; s1[i] != '\0'; i++)
	{
		c = s1[i];
		if (c > 127)
		{
			snprintf(buf2, sizeof buf2, "&#%d;", c);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -777,8 +777,9 @@
 			s->append_char(s, c);
 		}
 	}
-
-	memcpy(outbuffer, s->str, XMLRPC_BUFSIZE);
+	s->append_char(s, 0);
+
+	strncpy(outbuffer, s->str, XMLRPC_BUFSIZE);
 }
 
 static void xmlrpc_append_char_encode(mowgli_string_t *s, const char *s1)
```
