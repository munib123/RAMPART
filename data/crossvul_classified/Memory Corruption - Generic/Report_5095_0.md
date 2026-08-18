# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5095_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5095_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 163-203 of the vulnerable file.

			if (x == im->sx) {
				x = 0;
				y++;
				if (y == im->sy) {
					return im;
				}
				break;
			}
		}
	}

	gd_error("EOF before image was complete");
	gdImageDestroy(im);
	return 0;
}


/* {{{ gdCtxPrintf */
static void gdCtxPrintf(gdIOCtx * out, const char *format, ...)
{
	char buf[4096];
	int len;
	va_list args;

	va_start(args, format);
	len = vsnprintf(buf, sizeof(buf)-1, format, args);
	va_end(args);
	out->putBuf(out, buf, len);
}
/* }}} */

/* {{{ gdImageXbmCtx */
BGD_DECLARE(void) gdImageXbmCtx(gdImagePtr image, char* file_name, int fg, gdIOCtx * out)
{
	int x, y, c, b, sx, sy, p;
	char *name, *f;
	size_t i, l;

	name = file_name;
	if ((f = strrchr(name, '/')) != NULL) name = f+1;
	if ((f = strrchr(name, '\\')) != NULL) name = f+1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -180,7 +180,7 @@
 /* {{{ gdCtxPrintf */
 static void gdCtxPrintf(gdIOCtx * out, const char *format, ...)
 {
-	char buf[4096];
+	char buf[1024];
 	int len;
 	va_list args;
 
@@ -190,6 +190,9 @@
 	out->putBuf(out, buf, len);
 }
 /* }}} */
+
+/* The compiler will optimize strlen(constant) to a constant number. */
+#define gdCtxPuts(out, s) out->putBuf(out, s, strlen(s))
 
 /* {{{ gdImageXbmCtx */
 BGD_DECLARE(void) gdImageXbmCtx(gdImagePtr image, char* file_name, int fg, gdIOCtx * out)
@@ -215,9 +218,26 @@
 		}
 	}
 
-	gdCtxPrintf(out, "#define %s_width %d\n", name, gdImageSX(image));
-	gdCtxPrintf(out, "#define %s_height %d\n", name, gdImageSY(image));
-	gdCtxPrintf(out, "static unsigned char %s_bits[] = {\n  ", name);
+	/* Since "name" comes from the user, run it through a direct puts.
+	 * Trying to printf it into a local buffer means we'd need a large
+	 * or dynamic buffer to hold it all. */
+
+	/* #define <name>_width 1234 */
+	gdCtxPuts(out, "#define ");
+	gdCtxPuts(out, name);
+	gdCtxPuts(out, "_width ");
+	gdCtxPrintf(out, "%d\n", gdImageSX(image));
+
+	/* #define <name>_height 1234 */
+	gdCtxPuts(out, "#define ");
+	gdCtxPuts(out, name);
+	gdCtxPuts(out, "_height ");
+	gdCtxPrintf(out, "%d\n", gdImageSY(image));
+
+	/* static unsigned char <name>_bits[] = {\n */
+	gdCtxPuts(out, "static unsigned char ");
+	gdCtxPuts(out, name);
+	gdCtxPuts(out, "_bits[] = {\n  ");
 
 	free(name);
 
@@ -234,9 +254,9 @@
 			if ((b == 128) || (x == sx && y == sy)) {
 				b = 1;
 				if (p) {
-					gdCtxPrintf(out, ", ");
+					gdCtxPuts(out, ", ");
 					if (!(p%12)) {
-						gdCtxPrintf(out, "\n  ");
+						gdCtxPuts(out, "\n  ");
 						p = 12;
 					}
 				}
@@ -248,6 +268,6 @@
 			}
 		}
 	}
-	gdCtxPrintf(out, "};\n");
+	gdCtxPuts(out, "};\n");
 }
 /* }}} */
```
