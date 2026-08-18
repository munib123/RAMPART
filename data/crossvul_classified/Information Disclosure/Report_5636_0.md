# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5636_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5636_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 651-691 of the vulnerable file.

}

static inline uint32_t
buf_read_u32 (struct buffer *buf, bool *good)
{
  uint32_t ret;
  if (!buf_read (buf, &ret, sizeof (uint32_t)))
    {
      if (good)
	*good = false;
      return 0;
    }
  else
    {
      if (good)
	*good = true;
      return ntohl (ret);
    }
}

static inline bool
buf_string_match (const struct buffer *src, const void *match, int size)
{
  if (size != src->len)
    return false;
  return memcmp (BPTR (src), match, size) == 0;
}

static inline bool
buf_string_match_head (const struct buffer *src, const void *match, int size)
{
  if (size < 0 || size > src->len)
    return false;
  return memcmp (BPTR (src), match, size) == 0;
}

bool buf_string_match_head_str (const struct buffer *src, const char *match);
bool buf_string_compare_advance (struct buffer *src, const char *match);
int buf_substring_len (const struct buffer *buf, int delim);

/*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -668,6 +668,10 @@
     }
 }
 
+/**
+ * Compare src buffer contents with match.
+ * *NOT* constant time. Do not use when comparing HMACs.
+ */
 static inline bool
 buf_string_match (const struct buffer *src, const void *match, int size)
 {
@@ -676,6 +680,10 @@
   return memcmp (BPTR (src), match, size) == 0;
 }
 
+/**
+ * Compare first size bytes of src buffer contents with match.
+ * *NOT* constant time. Do not use when comparing HMACs.
+ */
 static inline bool
 buf_string_match_head (const struct buffer *src, const void *match, int size)
 {
```
