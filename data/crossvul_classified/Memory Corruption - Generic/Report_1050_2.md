# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1050_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1050_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 177-217 of the vulnerable file.

extern int rectelipse, polystar, regular_star;	/* from cvpalettes.c */
extern int center_out[2];			/* from cvpalettes.c */
extern float rr_radius;				/* from cvpalettes.c */
extern int ps_pointcnt;				/* from cvpalettes.c */
extern float star_percent;			/* from cvpalettes.c */
extern int home_char;				/* from fontview.c */
extern int compact_font_on_open;		/* from fontview.c */
extern int aa_pixelsize;			/* from anchorsaway.c */
extern enum cvtools cv_b1_tool, cv_cb1_tool, cv_b2_tool, cv_cb2_tool; /* cvpalettes.c */
extern int show_kerning_pane_in_class;		/* kernclass.c */
extern int AutoSaveFrequency;			/* autosave.c */
extern int UndoRedoLimitToSave;  /* sfd.c */
extern int UndoRedoLimitToLoad;  /* sfd.c */
extern int prefRevisionsToRetain; /* sfd.c */
extern int prefs_cv_show_control_points_always_initially; /* from charview.c */
extern int prefs_create_dragging_comparison_outline;      /* from charview.c */
extern int prefs_cv_outline_thickness; /* from charview.c */

extern float OpenTypeLoadHintEqualityTolerance;  /* autohint.c */
extern float GenerateHintWidthEqualityTolerance; /* splinesave.c */
extern NameList *force_names_when_opening;
extern NameList *force_names_when_saving;
extern NameList *namelist_for_new_fonts;

extern int default_font_filter_index;
extern struct openfilefilters *user_font_filters;
static int alwaysgenapple=false, alwaysgenopentype=false;

static int gfc_showhidden, gfc_dirplace;
static char *gfc_bookmarks=NULL;

static int prefs_usecairo = true;

static int pointless;

    /* These first three must match the values in macenc.c */
#define CID_Features	101
#define CID_FeatureDel	103
#define CID_FeatureEdit	105

#define CID_Mapping	102
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -194,6 +194,7 @@
 
 extern float OpenTypeLoadHintEqualityTolerance;  /* autohint.c */
 extern float GenerateHintWidthEqualityTolerance; /* splinesave.c */
+extern bool warn_script_unsaved; /* fontview.c */
 extern NameList *force_names_when_opening;
 extern NameList *force_names_when_saving;
 extern NameList *namelist_for_new_fonts;
@@ -311,6 +312,7 @@
 	{ N_("AutoSaveFrequency"), pr_int, &AutoSaveFrequency, NULL, NULL, '\0', NULL, 0, N_( "The number of seconds between autosaves. If you set this to 0 there will be no autosaves.") },
 	{ N_("RevisionsToRetain"), pr_int, &prefRevisionsToRetain, NULL, NULL, '\0', NULL, 0, N_( "When Saving, keep this number of previous versions of the file. file.sfd-01 will be the last saved file, file.sfd-02 will be the file saved before that, and so on. If you set this to 0 then no revisions will be retained.") },
 	{ N_("UndoRedoLimitToSave"), pr_int, &UndoRedoLimitToSave, NULL, NULL, '\0', NULL, 0, N_( "The number of undo and redo operations which will be saved in sfd files.\nIf you set this to 0 undo/redo information is not saved to sfd files.\nIf set to -1 then all available undo/redo information is saved without limit.") },
+	{ N_("WarnScriptUnsaved"), pr_bool, &warn_script_unsaved, NULL, NULL, '\0', NULL, 0, N_( "Whether or not to warn you if you have an unsaved script in the «Execute Script» dialog.") },
 	PREFS_LIST_EMPTY
 },
   new_list[] = {
```
