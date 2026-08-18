# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1050_6
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1050_6`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 389-429 of the vulnerable file.

void GGadgetsCreate(GWindow base, GGadgetCreateData *gcd);
int  GGadgetFillsWindow(GGadget *g);
int  GGadgetIsDefault(GGadget *g);

void GGadgetSetTitle(GGadget *g,const unichar_t *title);
void GGadgetSetTitle8(GGadget *g,const char *title);
void GGadgetSetTitle8WithMn(GGadget *g,const char *title);
const unichar_t *_GGadgetGetTitle(GGadget *g);	/* Do not free!!! */
unichar_t *GGadgetGetTitle(GGadget *g);		/* Free the return */
char *GGadgetGetTitle8(GGadget *g);		/* Free the return (utf8) */
void GGadgetSetFont(GGadget *g,GFont *font);
GFont *GGadgetGetFont(GGadget *g);
int GGadgetEditCmd(GGadget *g,enum editor_commands cmd);
int GGadgetActiveGadgetEditCmd(GWindow gw,enum editor_commands cmd);
void GGadgetSetHandler(GGadget *g, GGadgetHandler handler);
GGadgetHandler GGadgetGetHandler(GGadget *g);

void GTextFieldSelect(GGadget *g,int sel_start, int sel_end);
void GTextFieldShow(GGadget *g,int pos);
void GTextFieldReplace(GGadget *g,const unichar_t *txt);
void GCompletionFieldSetCompletion(GGadget *g,GTextCompletionHandler completion);
void GCompletionFieldSetCompletionMode(GGadget *g,int enabled);
void GGadgetClearList(GGadget *g);
void GGadgetSetList(GGadget *g, GTextInfo **ti, int32 copyit);
GTextInfo **GGadgetGetList(GGadget *g,int32 *len);	/* Do not free!!! */
GTextInfo *GGadgetGetListItem(GGadget *g,int32 pos);
GTextInfo *GGadgetGetListItemSelected(GGadget *g);
void GGadgetSelectListItem(GGadget *g,int32 pos,int32 sel);
void GGadgetSelectOneListItem(GGadget *g,int32 pos);
int32 GGadgetIsListItemSelected(GGadget *g,int32 pos);
int32 GGadgetGetFirstListSelectedItem(GGadget *g);
void GGadgetScrollListToPos(GGadget *g,int32 pos);
void GGadgetScrollListToText(GGadget *g,const unichar_t *lab,int32 sel);
void GGadgetSetListOrderer(GGadget *g,int (*orderer)(const void *, const void *));

void GColorButtonSetColor(GGadget *g, Color col);
Color GColorButtonGetColor(GGadget *g);

void GGadgetSetChecked(GGadget *g, int ison);
int GGadgetIsChecked(GGadget *g);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -406,6 +406,7 @@
 void GTextFieldSelect(GGadget *g,int sel_start, int sel_end);
 void GTextFieldShow(GGadget *g,int pos);
 void GTextFieldReplace(GGadget *g,const unichar_t *txt);
+bool GTextFieldIsEmpty(GGadget *g);
 void GCompletionFieldSetCompletion(GGadget *g,GTextCompletionHandler completion);
 void GCompletionFieldSetCompletionMode(GGadget *g,int enabled);
 void GGadgetClearList(GGadget *g);
```
