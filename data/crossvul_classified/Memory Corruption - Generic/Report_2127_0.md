# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2127_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2127_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1272-1312 of the vulnerable file.

			digit = toupper(c) - '0';
			if (digit > 10)
			    digit += '0' + 10 - 'A';
			value = (value << 4) + digit;
			c = getc (f);
		    }
		    got = 1;
		    break;
		}

		/*
		 * Otherwise the character stands for itself.
		 */
		value = c;
		break;
	    }

	    /*
	     * Store the resulting character for the escape sequence.
	     */
	    if (len < MAXWORDLEN-1)
		word[len] = value;
	    ++len;

	    if (!got)
		c = getc(f);
	    continue;
	}

	/*
	 * Backslash starts a new escape sequence.
	 */
	if (c == '\\') {
	    escape = 1;
	    c = getc(f);
	    continue;
	}

	/*
	 * Not escaped: check for the start or end of a quoted
	 * section and see if we've reached the end of the word.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1289,9 +1289,10 @@
 	    /*
 	     * Store the resulting character for the escape sequence.
 	     */
-	    if (len < MAXWORDLEN-1)
+	    if (len < MAXWORDLEN) {
 		word[len] = value;
-	    ++len;
+		++len;
+	    }
 
 	    if (!got)
 		c = getc(f);
@@ -1329,9 +1330,10 @@
 	/*
 	 * An ordinary character: store it in the word and get another.
 	 */
-	if (len < MAXWORDLEN-1)
+	if (len < MAXWORDLEN) {
 	    word[len] = c;
-	++len;
+	    ++len;
+	}
 
 	c = getc(f);
     }
```
