# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 345_10
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `345_10`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 322-363 of the vulnerable file.

			break;
		case SC_AC_SEN:
			strcpy(buf, "Sec.Env. ");
			if (e->key_ref != SC_AC_KEY_REF_NONE)
				sprintf(buf + 3, "#%d", e->key_ref);
			break;
		case SC_AC_SCB:
			strcpy(buf, "Sec.ControlByte ");
			if (e->key_ref != SC_AC_KEY_REF_NONE)
				sprintf(buf + 3, "Ox%X", e->key_ref);
			break;
		case SC_AC_IDA:
			strcpy(buf, "PKCS#15 AuthID ");
			if (e->key_ref != SC_AC_KEY_REF_NONE)
				sprintf(buf + 3, "#%d", e->key_ref);
			break;
		default:
			strcpy(buf, "????");
			break;
		}
		strcat(line, buf);
		strcat(line, " ");
		e = e->next;
	}
	line[strlen(line)-1] = 0; /* get rid of trailing space */
	return line;
}

NORETURN void
util_fatal(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	fprintf(stderr, "error: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\nAborting.\n");
	va_end(ap);

	sc_notify_close();

	exit(1);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -339,10 +339,11 @@
 			strcpy(buf, "????");
 			break;
 		}
-		strcat(line, buf);
-		strcat(line, " ");
+		strncat(line, buf, sizeof line);
+		strncat(line, " ", sizeof line);
 		e = e->next;
 	}
+	line[(sizeof line)-1] = '\0'; /* make sure it's NUL terminated */
 	line[strlen(line)-1] = 0; /* get rid of trailing space */
 	return line;
 }
```
