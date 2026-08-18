# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 914_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `914_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1290-1330 of the vulnerable file.

    }
    break;

  case BAG_IF_ELSE:
    {
      Node* cond = NODE_BAG_BODY(node);
      Node* Then = node->te.Then;
      Node* Else = node->te.Else;

      len = compile_length_tree(cond, reg);
      if (len < 0) return len;
      len += SIZE_OP_PUSH;
      len += SIZE_OP_ATOMIC_START + SIZE_OP_ATOMIC_END;

      if (IS_NOT_NULL(Then)) {
        tlen = compile_length_tree(Then, reg);
        if (tlen < 0) return tlen;
        len += tlen;
      }

      if (IS_NOT_NULL(Else)) {
        len += SIZE_OP_JUMP;
        tlen = compile_length_tree(Else, reg);
        if (tlen < 0) return tlen;
        len += tlen;
      }
    }
    break;

  case BAG_OPTION:
    /* never come here, but set for escape warning */
    len = 0;
    break;
  }

  return len;
}

static int get_char_len_node(Node* node, regex_t* reg, int* len);

static int
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1307,8 +1307,9 @@
         len += tlen;
       }
 
+      len += SIZE_OP_JUMP + SIZE_OP_ATOMIC_END;
+
       if (IS_NOT_NULL(Else)) {
-        len += SIZE_OP_JUMP;
         tlen = compile_length_tree(Else, reg);
         if (tlen < 0) return tlen;
         len += tlen;
@@ -1455,7 +1456,7 @@
 
   case BAG_IF_ELSE:
     {
-      int cond_len, then_len, jump_len;
+      int cond_len, then_len, else_len, jump_len;
       Node* cond = NODE_BAG_BODY(node);
       Node* Then = node->te.Then;
       Node* Else = node->te.Else;
@@ -1472,8 +1473,7 @@
       else
         then_len = 0;
 
-      jump_len = cond_len + then_len + SIZE_OP_ATOMIC_END;
-      if (IS_NOT_NULL(Else)) jump_len += SIZE_OP_JUMP;
+      jump_len = cond_len + then_len + SIZE_OP_ATOMIC_END + SIZE_OP_JUMP;
 
       r = add_op(reg, OP_PUSH);
       if (r != 0) return r;
@@ -1490,11 +1490,20 @@
       }
 
       if (IS_NOT_NULL(Else)) {
-        int else_len = compile_length_tree(Else, reg);
-        r = add_op(reg, OP_JUMP);
-        if (r != 0) return r;
-        COP(reg)->jump.addr = else_len + SIZE_INC_OP;
-
+        else_len = compile_length_tree(Else, reg);
+        if (else_len < 0) return else_len;
+      }
+      else
+        else_len = 0;
+
+      r = add_op(reg, OP_JUMP);
+      if (r != 0) return r;
+      COP(reg)->jump.addr = SIZE_OP_ATOMIC_END + else_len + SIZE_INC_OP;
+
+      r = add_op(reg, OP_ATOMIC_END);
+      if (r != 0) return r;
+
+      if (IS_NOT_NULL(Else)) {
         r = compile_tree(Else, reg, env);
       }
     }
```
