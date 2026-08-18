# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 528_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `528_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 36-76 of the vulnerable file.


  if(cancel_phantom)
    state->at_phantom = 0;

  if(state->callbacks && state->callbacks->movecursor)
    if((*state->callbacks->movecursor)(state->pos, *oldpos, state->mode.cursor_visible, state->cbdata))
      return;
}

static void erase(VTermState *state, VTermRect rect, int selective)
{
  if(state->callbacks && state->callbacks->erase)
    if((*state->callbacks->erase)(rect, selective, state->cbdata))
      return;
}

static VTermState *vterm_state_new(VTerm *vt)
{
  VTermState *state = vterm_allocator_malloc(vt, sizeof(VTermState));

  state->vt = vt;

  state->rows = vt->rows;
  state->cols = vt->cols;

  state->mouse_col     = 0;
  state->mouse_row     = 0;
  state->mouse_buttons = 0;

  state->mouse_protocol = MOUSE_X10;

  state->callbacks = NULL;
  state->cbdata    = NULL;

  vterm_state_newpen(state);

  state->bold_is_highbright = 0;

  return state;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,6 +53,8 @@
 {
   VTermState *state = vterm_allocator_malloc(vt, sizeof(VTermState));
 
+  if (state == NULL)
+    return NULL;
   state->vt = vt;
 
   state->rows = vt->rows;
@@ -1693,6 +1695,10 @@
   on_resize /* resize */
 };
 
+/*
+ * Return the existing state or create a new one.
+ * Returns NULL when out of memory.
+ */
 VTermState *vterm_obtain_state(VTerm *vt)
 {
   VTermState *state;
@@ -1700,6 +1706,8 @@
     return vt->state;
 
   state = vterm_state_new(vt);
+  if (state == NULL)
+    return NULL;
   vt->state = state;
 
   state->combine_chars_size = 16;
```
