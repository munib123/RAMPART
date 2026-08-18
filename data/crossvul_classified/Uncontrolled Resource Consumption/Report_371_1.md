# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 371_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `371_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 296-336 of the vulnerable file.

              if (lastPart) {
                urlParsePart(url, lastPart, ptr - lastPart);
              } else {
                if (ptr != buf) {
                  info("[http] Ignoring prologue before \"multipart/form-data\"!");
                }
              }
              lastPart     = part;
            } else if (!urlMemcmp(part, len, "--\r\n")) {
              len         -= 4;
              part        += 4;
              urlParsePart(url, lastPart, ptr - lastPart);
              lastPart     = NULL;
              if (len > 0) {
                info("[http] Ignoring epilogue past end of \"multipart/"
				     "form-data\"!");
              }
            }
          }
        }
      }
      if (lastPart) {
        warn("[http] Missing final \"boundary\" for \"multipart/form-data\"!");
      }
    } else {
      warn("[http] Missing \"boundary\" information for \"multipart/form-data\"!");
    }
  }
  destroyHashMap(&contentType);
}

struct URL *newURL(const struct HttpConnection *http,
                   const char *buf, int len) {
  struct URL *url;
  check(url = malloc(sizeof(struct URL)));
  initURL(url, http, buf, len);
  return url;
}

void initURL(struct URL *url, const struct HttpConnection *http,
             const char *buf, int len) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -313,6 +313,21 @@
             }
           }
         }
+        /* elf-2018.09.09: Detection of broken multipart/form-data
+           fixes DoS vulnerability.
+
+           On 9/9/18 10:43 AM, Imre Rad wrote:
+           Hi Markus, Marc!
+
+           I identified a vulnerability today in Shellinabox, it is
+           remote a denial of service, shellinaboxd eating up 100% cpu
+           and not processing subsequent requests after the attack was
+           mounted.
+        */
+        else {
+          warn ("[http] Ignorning broken multipart/form-data");
+          break;
+        }
       }
       if (lastPart) {
         warn("[http] Missing final \"boundary\" for \"multipart/form-data\"!");
```
