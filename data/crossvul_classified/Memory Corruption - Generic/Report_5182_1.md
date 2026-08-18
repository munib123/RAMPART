# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5182_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5182_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1450-1490 of the vulnerable file.

	return parse_path(state);
}

static const char *parse_scheme(struct parse_state *state)
{
	size_t mb;
	const char *tmp = state->ptr;

	do {
		switch (*state->ptr) {
		case ':':
			/* scheme delimiter */
			state->url.scheme = &state->buffer[0];
			state->buffer[state->offset++] = 0;
			return ++state->ptr;

		case '0': case '1': case '2': case '3': case '4': case '5': case '6':
		case '7': case '8': case '9':
		case '+': case '-': case '.':
			if (state->ptr == tmp) {
				return tmp;
			}
			/* no break */
		case 'A': case 'B': case 'C': case 'D': case 'E': case 'F': case 'G':
		case 'H': case 'I': case 'J': case 'K': case 'L': case 'M': case 'N':
		case 'O': case 'P': case 'Q': case 'R': case 'S': case 'T': case 'U':
		case 'V': case 'W': case 'X': case 'Y': case 'Z':
		case 'a': case 'b': case 'c': case 'd': case 'e': case 'f': case 'g':
		case 'h': case 'i': case 'j': case 'k': case 'l': case 'm': case 'n':
		case 'o': case 'p': case 'q': case 'r': case 's': case 't': case 'u':
		case 'v': case 'w': case 'x': case 'y': case 'z':
			/* scheme part */
			state->buffer[state->offset++] = *state->ptr;
			break;

		default:
			if (!(mb = parse_mb(state, PARSE_SCHEME, state->ptr, state->end, tmp, 1))) {
				/* soft fail; parse path next */
				return tmp;
			}
			state->ptr += mb - 1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1467,7 +1467,7 @@
 		case '7': case '8': case '9':
 		case '+': case '-': case '.':
 			if (state->ptr == tmp) {
-				return tmp;
+				goto softfail;
 			}
 			/* no break */
 		case 'A': case 'B': case 'C': case 'D': case 'E': case 'F': case 'G':
@@ -1484,19 +1484,20 @@
 
 		default:
 			if (!(mb = parse_mb(state, PARSE_SCHEME, state->ptr, state->end, tmp, 1))) {
-				/* soft fail; parse path next */
-				return tmp;
+				goto softfail;
 			}
 			state->ptr += mb - 1;
 		}
 	} while (++state->ptr != state->end);
 
+softfail:
+	state->offset = 0;
 	return state->ptr = tmp;
 }
 
 php_http_url_t *php_http_url_parse(const char *str, size_t len, unsigned flags TSRMLS_DC)
 {
-	size_t maxlen = 3 * len;
+	size_t maxlen = 3 * len + 8 /* null bytes for all components */;
 	struct parse_state *state = ecalloc(1, sizeof(*state) + maxlen);
 
 	state->end = str + len;
```
