# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5391_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5391_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 416-456 of the vulnerable file.

	case 1:								\
		__get_user_asm_ex(x, ptr, "b", "b", "=q");		\
		break;							\
	case 2:								\
		__get_user_asm_ex(x, ptr, "w", "w", "=r");		\
		break;							\
	case 4:								\
		__get_user_asm_ex(x, ptr, "l", "k", "=r");		\
		break;							\
	case 8:								\
		__get_user_asm_ex_u64(x, ptr);				\
		break;							\
	default:							\
		(x) = __get_user_bad();					\
	}								\
} while (0)

#define __get_user_asm_ex(x, addr, itype, rtype, ltype)			\
	asm volatile("1:	mov"itype" %1,%"rtype"0\n"		\
		     "2:\n"						\
		     _ASM_EXTABLE_EX(1b, 2b)				\
		     : ltype(x) : "m" (__m(addr)))

#define __put_user_nocheck(x, ptr, size)			\
({								\
	int __pu_err;						\
	__uaccess_begin();					\
	__put_user_size((x), (ptr), (size), __pu_err, -EFAULT);	\
	__uaccess_end();					\
	__builtin_expect(__pu_err, 0);				\
})

#define __get_user_nocheck(x, ptr, size)				\
({									\
	int __gu_err;							\
	__inttype(*(ptr)) __gu_val;					\
	__uaccess_begin();						\
	__get_user_size(__gu_val, (ptr), (size), __gu_err, -EFAULT);	\
	__uaccess_end();						\
	(x) = (__force __typeof__(*(ptr)))__gu_val;			\
	__builtin_expect(__gu_err, 0);					\
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -433,7 +433,11 @@
 #define __get_user_asm_ex(x, addr, itype, rtype, ltype)			\
 	asm volatile("1:	mov"itype" %1,%"rtype"0\n"		\
 		     "2:\n"						\
-		     _ASM_EXTABLE_EX(1b, 2b)				\
+		     ".section .fixup,\"ax\"\n"				\
+                     "3:xor"itype" %"rtype"0,%"rtype"0\n"		\
+		     "  jmp 2b\n"					\
+		     ".previous\n"					\
+		     _ASM_EXTABLE_EX(1b, 3b)				\
 		     : ltype(x) : "m" (__m(addr)))
 
 #define __put_user_nocheck(x, ptr, size)			\
```
