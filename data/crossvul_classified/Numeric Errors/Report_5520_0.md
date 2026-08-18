# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 5520_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5520_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 44-84 of the vulnerable file.

  string->log_clusters = NULL;

  return string;
}

/**
 * pango_glyph_string_set_size:
 * @string:    a #PangoGlyphString.
 * @new_len:   the new length of the string.
 *
 * Resize a glyph string to the given length.
 */
void
pango_glyph_string_set_size (PangoGlyphString *string, gint new_len)
{
  g_return_if_fail (new_len >= 0);

  while (new_len > string->space)
    {
      if (string->space == 0)
	string->space = 1;
      else
	string->space *= 2;

      if (string->space < 0)
	{
	  g_warning ("glyph string length overflows maximum integer size, truncated");
	  new_len = string->space = G_MAXINT - 8;
	}
    }

  string->glyphs = g_realloc (string->glyphs, string->space * sizeof (PangoGlyphInfo));
  string->log_clusters = g_realloc (string->log_clusters, string->space * sizeof (gint));
  string->num_glyphs = new_len;
}

GType
pango_glyph_string_get_type (void)
{
  static GType our_type = 0;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,14 +61,28 @@
   while (new_len > string->space)
     {
       if (string->space == 0)
-	string->space = 1;
+	{
+	  string->space = 4;
+	}
       else
-	string->space *= 2;
-
-      if (string->space < 0)
-	{
-	  g_warning ("glyph string length overflows maximum integer size, truncated");
-	  new_len = string->space = G_MAXINT - 8;
+	{
+	  const guint max_space =
+	    MIN (G_MAXINT, G_MAXSIZE / MAX (sizeof(PangoGlyphInfo), sizeof(gint)));
+
+	  guint more_space = (guint)string->space * 2;
+
+	  if (more_space > max_space)
+	    {
+	      more_space = max_space;
+
+	      if ((guint)new_len > max_space)
+		{
+		  g_error ("%s: failed to allocate glyph string of length %i\n",
+			   G_STRLOC, new_len);
+		}
+	    }
+
+	  string->space = more_space;
 	}
     }
 
```
