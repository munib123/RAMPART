# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 3348_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3348_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 17-57 of the vulnerable file.


THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#define _GNU_SOURCE

#include <string.h>
#include <assert.h>
#include <time.h>
#include <math.h>

#include <yara/endian.h>
#include <yara/exec.h>
#include <yara/limits.h>
#include <yara/error.h>
#include <yara/object.h>
#include <yara/modules.h>
#include <yara/re.h>
#include <yara/strutils.h>
#include <yara/utils.h>
#include <yara/mem.h>

#include <yara.h>


#define MEM_SIZE   MAX_LOOP_NESTING * LOOP_LOCAL_VARS


#define push(x)  \
    if (sp < stack_size) \
    { \
      stack[sp++] = (x); \
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,6 +34,7 @@
 #include <time.h>
 #include <math.h>
 
+#include <yara/arena.h>
 #include <yara/endian.h>
 #include <yara/exec.h>
 #include <yara/limits.h>
@@ -177,6 +178,8 @@
   YR_RULE* rule;
   YR_MATCH* match;
   YR_OBJECT_FUNCTION* function;
+  YR_OBJECT** obj_ptr;
+  YR_ARENA* obj_arena;
 
   char* identifier;
   char* args_fmt;
@@ -201,6 +204,10 @@
   if (stack == NULL)
     return ERROR_INSUFFICIENT_MEMORY;
 
+  FAIL_ON_ERROR_WITH_CLEANUP(
+      yr_arena_create(1024, 0, &obj_arena),
+      yr_free(stack));
+
   while(!stop)
   {
     switch(*ip)
@@ -437,6 +444,8 @@
         rule->clock_ticks += clock() - start;
         start = clock();
         #endif
+
+        assert(sp == 0);
         break;
 
       case OP_OBJ_LOAD:
@@ -577,18 +586,26 @@
           }
         }
 
+        // if i == MAX_OVERLOADED_FUNCTIONS at this point no matching
+        // prototype was found, but this shouldn't happen.
+
         assert(i < MAX_OVERLOADED_FUNCTIONS);
 
+        // make a copy of the returned object and push the copy into the stack
+        // function->return_obj can't be pushed because it can change in
+        // subsequent calls to the same function.
+
         if (result == ERROR_SUCCESS)
-        {
-          r1.o = function->return_obj;
-          push(r1);
-        }
-        else
-        {
-          stop = TRUE;
-        }
-
+          result = yr_object_copy(function->return_obj, &r1.o);
+
+        // a pointer to the copied object is stored in a arena in order to
+        // free the object before exiting yr_execute_code
+
+        if (result == ERROR_SUCCESS)
+          result = yr_arena_write_data(obj_arena, &r1.o, sizeof(r1.o), NULL);
+
+        stop = (result != ERROR_SUCCESS);
+        push(r1);
         break;
 
       case OP_FOUND:
@@ -1146,6 +1163,17 @@
     ip++;
   }
 
+  obj_ptr = (YR_OBJECT**) yr_arena_base_address(obj_arena);
+
+  while (obj_ptr != NULL)
+  {
+    yr_object_destroy(*obj_ptr);
+
+    obj_ptr = (YR_OBJECT**) yr_arena_next_address(
+        obj_arena, obj_ptr, sizeof(YR_OBJECT*));
+  }
+
+  yr_arena_destroy(obj_arena);
   yr_modules_unload_all(context);
   yr_free(stack);
 
```
