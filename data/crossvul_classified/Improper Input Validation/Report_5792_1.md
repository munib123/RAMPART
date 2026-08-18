# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5792_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5792_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 84-124 of the vulnerable file.

		: "=&r" (flag), "=&r" (roksum) \
		: "r" (addr), "Ir" (size), "0" (current_thread_info()->addr_limit) \
		: "cc"); \
	flag; })

/*
 * Single-value transfer routines.  They automatically use the right
 * size if we just have the right pointer type.  Note that the functions
 * which read from user space (*get_*) need to take care not to leak
 * kernel data even if the calling code is buggy and fails to check
 * the return value.  This means zeroing out the destination variable
 * or buffer on error.  Normally this is done out of line by the
 * fixup code, but there are a few places where it intrudes on the
 * main code path.  When we only write to user space, there is no
 * problem.
 */
extern int __get_user_1(void *);
extern int __get_user_2(void *);
extern int __get_user_4(void *);

#define __get_user_x(__r2,__p,__e,__s,__i...)				\
	   __asm__ __volatile__ (					\
		__asmeq("%0", "r0") __asmeq("%1", "r2")			\
		"bl	__get_user_" #__s				\
		: "=&r" (__e), "=r" (__r2)				\
		: "0" (__p)						\
		: __i, "cc")

#define get_user(x,p)							\
	({								\
		register const typeof(*(p)) __user *__p asm("r0") = (p);\
		register unsigned long __r2 asm("r2");			\
		register int __e asm("r0");				\
		switch (sizeof(*(__p))) {				\
		case 1:							\
			__get_user_x(__r2, __p, __e, 1, "lr");		\
	       		break;						\
		case 2:							\
			__get_user_x(__r2, __p, __e, 2, "r3", "lr");	\
			break;						\
		case 4:							\
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -101,28 +101,39 @@
 extern int __get_user_2(void *);
 extern int __get_user_4(void *);
 
-#define __get_user_x(__r2,__p,__e,__s,__i...)				\
+#define __GUP_CLOBBER_1	"lr", "cc"
+#ifdef CONFIG_CPU_USE_DOMAINS
+#define __GUP_CLOBBER_2	"ip", "lr", "cc"
+#else
+#define __GUP_CLOBBER_2 "lr", "cc"
+#endif
+#define __GUP_CLOBBER_4	"lr", "cc"
+
+#define __get_user_x(__r2,__p,__e,__l,__s)				\
 	   __asm__ __volatile__ (					\
 		__asmeq("%0", "r0") __asmeq("%1", "r2")			\
+		__asmeq("%3", "r1")					\
 		"bl	__get_user_" #__s				\
 		: "=&r" (__e), "=r" (__r2)				\
-		: "0" (__p)						\
-		: __i, "cc")
+		: "0" (__p), "r" (__l)					\
+		: __GUP_CLOBBER_##__s)
 
 #define get_user(x,p)							\
 	({								\
+		unsigned long __limit = current_thread_info()->addr_limit - 1; \
 		register const typeof(*(p)) __user *__p asm("r0") = (p);\
 		register unsigned long __r2 asm("r2");			\
+		register unsigned long __l asm("r1") = __limit;		\
 		register int __e asm("r0");				\
 		switch (sizeof(*(__p))) {				\
 		case 1:							\
-			__get_user_x(__r2, __p, __e, 1, "lr");		\
-	       		break;						\
+			__get_user_x(__r2, __p, __e, __l, 1);		\
+			break;						\
 		case 2:							\
-			__get_user_x(__r2, __p, __e, 2, "r3", "lr");	\
+			__get_user_x(__r2, __p, __e, __l, 2);		\
 			break;						\
 		case 4:							\
-	       		__get_user_x(__r2, __p, __e, 4, "lr");		\
+			__get_user_x(__r2, __p, __e, __l, 4);		\
 			break;						\
 		default: __e = __get_user_bad(); break;			\
 		}							\
@@ -135,31 +146,34 @@
 extern int __put_user_4(void *, unsigned int);
 extern int __put_user_8(void *, unsigned long long);
 
-#define __put_user_x(__r2,__p,__e,__s)					\
+#define __put_user_x(__r2,__p,__e,__l,__s)				\
 	   __asm__ __volatile__ (					\
 		__asmeq("%0", "r0") __asmeq("%2", "r2")			\
+		__asmeq("%3", "r1")					\
 		"bl	__put_user_" #__s				\
 		: "=&r" (__e)						\
-		: "0" (__p), "r" (__r2)					\
+		: "0" (__p), "r" (__r2), "r" (__l)			\
 		: "ip", "lr", "cc")
 
 #define put_user(x,p)							\
 	({								\
+		unsigned long __limit = current_thread_info()->addr_limit - 1; \
 		register const typeof(*(p)) __r2 asm("r2") = (x);	\
 		register const typeof(*(p)) __user *__p asm("r0") = (p);\
+		register unsigned long __l asm("r1") = __limit;		\
 		register int __e asm("r0");				\
 		switch (sizeof(*(__p))) {				\
 		case 1:							\
-			__put_user_x(__r2, __p, __e, 1);		\
+			__put_user_x(__r2, __p, __e, __l, 1);		\
 			break;						\
 		case 2:							\
-			__put_user_x(__r2, __p, __e, 2);		\
+			__put_user_x(__r2, __p, __e, __l, 2);		\
 			break;						\
 		case 4:							\
-			__put_user_x(__r2, __p, __e, 4);		\
+			__put_user_x(__r2, __p, __e, __l, 4);		\
 			break;						\
 		case 8:							\
-			__put_user_x(__r2, __p, __e, 8);		\
+			__put_user_x(__r2, __p, __e, __l, 8);		\
 			break;						\
 		default: __e = __put_user_bad(); break;			\
 		}							\
```
