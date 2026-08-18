# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3667_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3667_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 8-48 of the vulnerable file.

 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unwind.h>
#include <dlfcn.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/system_properties.h>

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,26 +25,26 @@
  * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
  * SUCH DAMAGE.
  */
+
+#include <dlfcn.h>
 #include <errno.h>
+#include <fcntl.h>
 #include <pthread.h>
+#include <stdarg.h>
+#include <stddef.h>
+#include <stdint.h>
 #include <stdio.h>
-#include <arpa/inet.h>
-#include <sys/socket.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
-#include <errno.h>
-#include <stddef.h>
-#include <stdarg.h>
-#include <fcntl.h>
 #include <unwind.h>
-#include <dlfcn.h>
-
+
+#include <arpa/inet.h>
+#include <sys/select.h>
 #include <sys/socket.h>
+#include <sys/system_properties.h>
+#include <sys/types.h>
 #include <sys/un.h>
-#include <sys/select.h>
-#include <sys/types.h>
-#include <sys/system_properties.h>
 
 #include "dlmalloc.h"
 #include "logd.h"
@@ -372,7 +372,11 @@
 
 void* chk_malloc(size_t bytes)
 {
-    char* buffer = (char*)dlmalloc(bytes + CHK_OVERHEAD_SIZE);
+    size_t size = bytes + CHK_OVERHEAD_SIZE;
+    if (size < bytes) { // Overflow.
+        return NULL;
+    }
+    uint8_t* buffer = (uint8_t*) dlmalloc(size);
     if (buffer) {
         memset(buffer, CHK_SENTINEL_VALUE, bytes + CHK_OVERHEAD_SIZE);
         size_t offset = dlmalloc_usable_size(buffer) - sizeof(size_t);
@@ -505,7 +509,12 @@
     // 1. allocate enough memory and include our header
     // 2. set the base pointer to be right after our header
 
-    void* base = dlmalloc(bytes + sizeof(AllocationEntry));
+    size_t size = bytes + sizeof(AllocationEntry);
+    if (size < bytes) { // Overflow.
+        return NULL;
+    }
+
+    void* base = dlmalloc(size);
     if (base != NULL) {
         pthread_mutex_lock(&gAllocationsMutex);
 
@@ -615,6 +624,10 @@
     // we will align by at least MALLOC_ALIGNMENT bytes
     // and at most alignment-MALLOC_ALIGNMENT bytes
     size_t size = (alignment-MALLOC_ALIGNMENT) + bytes;
+    if (size < bytes) { // Overflow.
+        return NULL;
+    }
+
     void* base = leak_malloc(size);
     if (base != NULL) {
         intptr_t ptr = (intptr_t)base;
```
