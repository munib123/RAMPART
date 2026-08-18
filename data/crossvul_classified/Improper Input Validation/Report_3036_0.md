# CrossVul Fix Pair: Improper Input Validation in go
**Pair ID:** 3036_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3036_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```go
Lines 103-150 of the vulnerable file.

}
#else
unsigned int get_major_version()
{
       return (unsigned int)SCMP_MAJOR_VERSION;
}

unsigned int get_minor_version()
{
       return (unsigned int)SCMP_MINOR_VERSION;
}

unsigned int get_micro_version()
{
       return (unsigned int)SCMP_MICRO_VERSION;
}
#endif

typedef struct scmp_arg_cmp* scmp_cast_t;

// Wrapper to create an scmp_arg_cmp struct
void*
make_struct_arg_cmp(
                    unsigned int arg,
                    int compare,
                    uint64_t a,
                    uint64_t b
                   )
{
	struct scmp_arg_cmp *s = malloc(sizeof(struct scmp_arg_cmp));

	s->arg = arg;
	s->op = compare;
	s->datum_a = a;
	s->datum_b = b;

	return s;
}
*/
import "C"

// Nonexported types
type scmpFilterAttr uint32

// Nonexported constants

const (
	filterAttrActDefault scmpFilterAttr = iota
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -120,23 +120,27 @@
 
 typedef struct scmp_arg_cmp* scmp_cast_t;
 
-// Wrapper to create an scmp_arg_cmp struct
-void*
-make_struct_arg_cmp(
-                    unsigned int arg,
-                    int compare,
-                    uint64_t a,
-                    uint64_t b
-                   )
-{
-	struct scmp_arg_cmp *s = malloc(sizeof(struct scmp_arg_cmp));
-
-	s->arg = arg;
-	s->op = compare;
-	s->datum_a = a;
-	s->datum_b = b;
-
-	return s;
+void* make_arg_cmp_array(unsigned int length)
+{
+        return calloc(length, sizeof(struct scmp_arg_cmp));
+}
+
+// Wrapper to add an scmp_arg_cmp struct to an existing arg_cmp array
+void add_struct_arg_cmp(
+                        struct scmp_arg_cmp* arr,
+                        unsigned int pos,
+                        unsigned int arg,
+                        int compare,
+                        uint64_t a,
+                        uint64_t b
+                       )
+{
+        arr[pos].arg = arg;
+        arr[pos].op = compare;
+        arr[pos].datum_a = a;
+        arr[pos].datum_b = b;
+
+        return;
 }
 */
 import "C"
@@ -239,12 +243,9 @@
 // DOES NOT LOCK OR CHECK VALIDITY
 // Assumes caller has already done this
 // Wrapper for seccomp_rule_add_... functions
-func (f *ScmpFilter) addRuleWrapper(call ScmpSyscall, action ScmpAction, exact bool, cond C.scmp_cast_t) error {
-	var length C.uint
-	if cond != nil {
-		length = 1
-	} else {
-		length = 0
+func (f *ScmpFilter) addRuleWrapper(call ScmpSyscall, action ScmpAction, exact bool, length C.uint, cond C.scmp_cast_t) error {
+	if length != 0 && cond == nil {
+		return fmt.Errorf("null conditions list, but length is nonzero")
 	}
 
 	var retCode C.int
@@ -258,6 +259,8 @@
 		return fmt.Errorf("unrecognized syscall")
 	} else if syscall.Errno(-1*retCode) == syscall.EPERM {
 		return fmt.Errorf("requested action matches default action of filter")
+	} else if syscall.Errno(-1*retCode) == syscall.EINVAL {
+		return fmt.Errorf("two checks on same syscall argument")
 	} else if retCode != 0 {
 		return syscall.Errno(-1 * retCode)
 	}
@@ -275,7 +278,7 @@
 	}
 
 	if len(conds) == 0 {
-		if err := f.addRuleWrapper(call, action, exact, nil); err != nil {
+		if err := f.addRuleWrapper(call, action, exact, 0, nil); err != nil {
 			return err
 		}
 	} else {
@@ -287,13 +290,20 @@
 			}
 		}
 
-		for _, cond := range conds {
-			cmpStruct := C.make_struct_arg_cmp(C.uint(cond.Argument), cond.Op.toNative(), C.uint64_t(cond.Operand1), C.uint64_t(cond.Operand2))
-			defer C.free(cmpStruct)
-
-			if err := f.addRuleWrapper(call, action, exact, C.scmp_cast_t(cmpStruct)); err != nil {
-				return err
-			}
+		argsArr := C.make_arg_cmp_array(C.uint(len(conds)))
+		if argsArr == nil {
+			return fmt.Errorf("error allocating memory for conditions")
+		}
+		defer C.free(argsArr)
+
+		for i, cond := range conds {
+			C.add_struct_arg_cmp(C.scmp_cast_t(argsArr), C.uint(i),
+				C.uint(cond.Argument), cond.Op.toNative(),
+				C.uint64_t(cond.Operand1), C.uint64_t(cond.Operand2))
+		}
+
+		if err := f.addRuleWrapper(call, action, exact, C.uint(len(conds)), C.scmp_cast_t(argsArr)); err != nil {
+			return err
 		}
 	}
 
```
