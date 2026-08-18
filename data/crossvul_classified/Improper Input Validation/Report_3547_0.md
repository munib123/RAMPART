# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3547_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3547_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1-36 of the vulnerable file.

/*
 *	Declarations of Rose type objects.
 *
 *	Jonathan Naylor G4KLX	25/8/96
 */

#ifndef _ROSE_H
#define _ROSE_H 

#include <linux/rose.h>
#include <net/sock.h>

#define	ROSE_ADDR_LEN			5

#define	ROSE_MIN_LEN			3

#define	ROSE_GFI			0x10
#define	ROSE_Q_BIT			0x80
#define	ROSE_D_BIT			0x40
#define	ROSE_M_BIT			0x10

#define	ROSE_CALL_REQUEST		0x0B
#define	ROSE_CALL_ACCEPTED		0x0F
#define	ROSE_CLEAR_REQUEST		0x13
#define	ROSE_CLEAR_CONFIRMATION		0x17
#define	ROSE_DATA			0x00
#define	ROSE_INTERRUPT			0x23
#define	ROSE_INTERRUPT_CONFIRMATION	0x27
#define	ROSE_RR				0x01
#define	ROSE_RNR			0x05
#define	ROSE_REJ			0x09
#define	ROSE_RESET_REQUEST		0x1B
#define	ROSE_RESET_CONFIRMATION		0x1F
#define	ROSE_REGISTRATION_REQUEST	0xF3
#define	ROSE_REGISTRATION_CONFIRMATION	0xF7
#define	ROSE_RESTART_REQUEST		0xFB
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,6 +13,12 @@
 #define	ROSE_ADDR_LEN			5
 
 #define	ROSE_MIN_LEN			3
+
+#define	ROSE_CALL_REQ_ADDR_LEN_OFF	3
+#define	ROSE_CALL_REQ_ADDR_LEN_VAL	0xAA	/* each address is 10 digits */
+#define	ROSE_CALL_REQ_DEST_ADDR_OFF	4
+#define	ROSE_CALL_REQ_SRC_ADDR_OFF	9
+#define	ROSE_CALL_REQ_FACILITIES_OFF	14
 
 #define	ROSE_GFI			0x10
 #define	ROSE_Q_BIT			0x80
@@ -214,7 +220,7 @@
 extern int  rose_validate_nr(struct sock *, unsigned short);
 extern void rose_write_internal(struct sock *, int);
 extern int  rose_decode(struct sk_buff *, int *, int *, int *, int *, int *);
-extern int  rose_parse_facilities(unsigned char *, struct rose_facilities_struct *);
+extern int  rose_parse_facilities(unsigned char *, unsigned int, struct rose_facilities_struct *);
 extern void rose_disconnect(struct sock *, int, int, int);
 
 /* rose_timer.c */
```
