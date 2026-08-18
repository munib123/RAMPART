# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5094_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5094_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 431-470 of the vulnerable file.

							zlog(ZLOG_WARNING, "missing closing embrace in the access.format");
							return -1;
						}
					}
					break;

				default:
					zlog(ZLOG_WARNING, "Invalid token in the access.format (%%%c)", *s);
					return -1;
			}

			if (*s != '}' && format[0] != '\0') {
				zlog(ZLOG_WARNING, "embrace is not allowed for modifier %%%c", *s);
				return -1;
			}
			s++;
			if (!test) {
				b += len2;
				len += len2;
			}
			continue;
		}

		if (!test) {
			// push the normal char to the output buffer
			*b = *s;
			b++;
			len++;
		}
		s++;
	}

	if (!test && strlen(buffer) > 0) {
		buffer[len] = '\n';
		write(fpm_log_fd, buffer, len + 1);
	}

	return 0;
}
/* }}} */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -448,6 +448,11 @@
 				b += len2;
 				len += len2;
 			}
+			if (len >= FPM_LOG_BUFFER) {
+				zlog(ZLOG_NOTICE, "the log buffer is full (%d). The access log request has been truncated.", FPM_LOG_BUFFER);
+				len = FPM_LOG_BUFFER;
+				break;
+			}
 			continue;
 		}
 
```
