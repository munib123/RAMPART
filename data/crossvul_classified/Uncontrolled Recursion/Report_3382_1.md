# CrossVul Fix Pair: Uncontrolled Recursion in c
**Pair ID:** 3382_1
**Vulnerability Class:** Uncontrolled Recursion
**CWE:** CWE-674
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3382_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Recursion - The product does not properly control the amount of recursion that takes place, consuming excessive resources, such as allocated memory or the program stack.

## Vulnerable Code
```c
Lines 119-159 of the vulnerable file.

  union {
    int mask;
    int end;
  };

  int greedy;

  uint8_t* class_vector;

  RE_NODE* left;
  RE_NODE* right;

  uint8_t* forward_code;
  uint8_t* backward_code;
};


struct RE_AST
{
  uint32_t flags;
  RE_NODE* root_node;
};


// Disable warning due to zero length array in Microsoft's compiler

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4200)
#endif

struct RE
{
  uint32_t flags;
  uint8_t code[0];
};

#ifdef _MSC_VER
#pragma warning(pop)
#endif

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -136,6 +136,7 @@
 struct RE_AST
 {
   uint32_t flags;
+  uint16_t levels;
   RE_NODE* root_node;
 };
 
```
