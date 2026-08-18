# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1050_4
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1050_4`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 192-232 of the vulnerable file.


static int utf82u_index(int pos, const char *start) {
    int uc = 0;
    const char *end = start+pos;

    while ( start<end ) {
	utf8_ildb(&start);
	++uc;
    }
return( uc );
}

static void GTextFieldChanged(GTextField *gt,int src) {
    GEvent e;

    e.type = et_controlevent;
    e.w = gt->g.base;
    e.u.control.subtype = et_textchanged;
    e.u.control.g = &gt->g;
    e.u.control.u.tf_changed.from_pulldown = src;
    if ( gt->g.handle_controlevent != NULL )
	(gt->g.handle_controlevent)(&gt->g,&e);
    else
	GDrawPostEvent(&e);
}

static void GTextFieldFocusChanged(GTextField *gt,int gained) {
    GEvent e;

    if ( (gt->g.box->flags & box_active_border_inner) &&
	    ( gt->g.state==gs_enabled || gt->g.state==gs_active )) {
	int state = gained?gs_active:gs_enabled;
	if ( state!=gt->g.state ) {
	    gt->g.state = state;
	    GGadgetRedraw((GGadget *) gt);
	}
    }
    e.type = et_controlevent;
    e.w = gt->g.base;
    e.u.control.subtype = et_textfocuschanged;
    e.u.control.g = &gt->g;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -209,6 +209,19 @@
     e.u.control.subtype = et_textchanged;
     e.u.control.g = &gt->g;
     e.u.control.u.tf_changed.from_pulldown = src;
+    if ( gt->g.handle_controlevent != NULL )
+	(gt->g.handle_controlevent)(&gt->g,&e);
+    else
+	GDrawPostEvent(&e);
+}
+
+static void GTextFieldSaved(GTextField *gt) {
+    GEvent e;
+
+    e.type = et_controlevent;
+    e.w = gt->g.base;
+    e.u.control.subtype = et_save;
+    e.u.control.g = &gt->g;
     if ( gt->g.handle_controlevent != NULL )
 	(gt->g.handle_controlevent)(&gt->g,&e);
     else
@@ -878,6 +891,11 @@
 static unichar_t errort[] = { 'C','o','u','l','d',' ','n','o','t',' ','o','p','e','n',  '\0' };
 static unichar_t error[] = { 'C','o','u','l','d',' ','n','o','t',' ','o','p','e','n',' ','%','.','1','0','0','h','s',  '\0' };
 
+bool GTextFieldIsEmpty(GGadget *g) {
+    GTextField *gt = (GTextField *) g;
+    return gt->text == NULL || *gt->text == '\0';
+}
+
 static void GTextFieldImport(GTextField *gt) {
     unichar_t *ret;
     char *cret;
@@ -970,6 +988,7 @@
 	}
     }
     fclose(file);
+    GTextFieldSaved(gt);
 }
 
 #define MID_Cut		1
```
