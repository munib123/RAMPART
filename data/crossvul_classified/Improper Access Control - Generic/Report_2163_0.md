# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2163_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2163_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 50-90 of the vulnerable file.

#define EXIT_REASON_VMWRITE             25
#define EXIT_REASON_VMOFF               26
#define EXIT_REASON_VMON                27
#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_DR_ACCESS           29
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32
#define EXIT_REASON_INVALID_STATE       33
#define EXIT_REASON_MWAIT_INSTRUCTION   36
#define EXIT_REASON_MONITOR_INSTRUCTION 39
#define EXIT_REASON_PAUSE_INSTRUCTION   40
#define EXIT_REASON_MCE_DURING_VMENTRY  41
#define EXIT_REASON_TPR_BELOW_THRESHOLD 43
#define EXIT_REASON_APIC_ACCESS         44
#define EXIT_REASON_EOI_INDUCED         45
#define EXIT_REASON_EPT_VIOLATION       48
#define EXIT_REASON_EPT_MISCONFIG       49
#define EXIT_REASON_INVEPT              50
#define EXIT_REASON_PREEMPTION_TIMER    52
#define EXIT_REASON_WBINVD              54
#define EXIT_REASON_XSETBV              55
#define EXIT_REASON_APIC_WRITE          56
#define EXIT_REASON_INVPCID             58

#define VMX_EXIT_REASONS \
	{ EXIT_REASON_EXCEPTION_NMI,         "EXCEPTION_NMI" }, \
	{ EXIT_REASON_EXTERNAL_INTERRUPT,    "EXTERNAL_INTERRUPT" }, \
	{ EXIT_REASON_TRIPLE_FAULT,          "TRIPLE_FAULT" }, \
	{ EXIT_REASON_PENDING_INTERRUPT,     "PENDING_INTERRUPT" }, \
	{ EXIT_REASON_NMI_WINDOW,            "NMI_WINDOW" }, \
	{ EXIT_REASON_TASK_SWITCH,           "TASK_SWITCH" }, \
	{ EXIT_REASON_CPUID,                 "CPUID" }, \
	{ EXIT_REASON_HLT,                   "HLT" }, \
	{ EXIT_REASON_INVLPG,                "INVLPG" }, \
	{ EXIT_REASON_RDPMC,                 "RDPMC" }, \
	{ EXIT_REASON_RDTSC,                 "RDTSC" }, \
	{ EXIT_REASON_VMCALL,                "VMCALL" }, \
	{ EXIT_REASON_VMCLEAR,               "VMCLEAR" }, \
	{ EXIT_REASON_VMLAUNCH,              "VMLAUNCH" }, \
	{ EXIT_REASON_VMPTRLD,               "VMPTRLD" }, \
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -67,6 +67,7 @@
 #define EXIT_REASON_EPT_MISCONFIG       49
 #define EXIT_REASON_INVEPT              50
 #define EXIT_REASON_PREEMPTION_TIMER    52
+#define EXIT_REASON_INVVPID             53
 #define EXIT_REASON_WBINVD              54
 #define EXIT_REASON_XSETBV              55
 #define EXIT_REASON_APIC_WRITE          56
@@ -114,6 +115,7 @@
 	{ EXIT_REASON_EOI_INDUCED,           "EOI_INDUCED" }, \
 	{ EXIT_REASON_INVALID_STATE,         "INVALID_STATE" }, \
 	{ EXIT_REASON_INVD,                  "INVD" }, \
+	{ EXIT_REASON_INVVPID,               "INVVPID" }, \
 	{ EXIT_REASON_INVPCID,               "INVPCID" }
 
 #endif /* _UAPIVMX_H */
```
