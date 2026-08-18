# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1869_4
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1869_4`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 144-184 of the vulnerable file.

+ (int)adaptiveFrameRateThroughputThreshold;
+ (BOOL)includePasteHistoryInAdvancedPaste;
+ (BOOL)experimentalKeyHandling;
+ (double)hotKeyDoubleTapMaxDelay;
+ (BOOL)hideStuckTooltips;
+ (BOOL)indicateBellsInDockBadgeLabel;
+ (double)tabFlashAnimationDuration;
+ (NSString *)downloadsDirectory;
+ (double)pointSizeOfTimeStamp;
+ (BOOL)showYellowMarkForJobStoppedBySignal;
+ (double)slowFrameRate;
+ (double)timeBetweenTips;
+ (void)setTimeBetweenTips:(double)time;
+ (BOOL)openFileOverridesSendText;
+ (BOOL)useLayers;
+ (int)terminalMargin;
+ (int)terminalVMargin;
+ (BOOL)useColorfgbgFallback;
+ (BOOL)promptForPasteWhenNotAtPrompt;
+ (void)setPromptForPasteWhenNotAtPrompt:(BOOL)value;
+ (BOOL)performDNSLookups;
+ (BOOL)zeroWidthSpaceAdvancesCursor;
+ (BOOL)darkThemeHasBlackTitlebar;
+ (BOOL)fontChangeAffectsBroadcastingSessions;
+ (BOOL)zippyTextDrawing;
+ (BOOL)noSyncSuppressClipboardAccessDeniedWarning;
+ (void)setNoSyncSuppressClipboardAccessDeniedWarning:(BOOL)value;
+ (BOOL)noSyncSuppressMissingProfileInArrangementWarning;
+ (void)setNoSyncSuppressMissingProfileInArrangementWarning:(BOOL)value;
+ (BOOL)acceptOSC7;
+ (BOOL)trackingRunloopForLiveResize;
+ (BOOL)enableAPIServer;
+ (double)shortLivedSessionDuration;
+ (int)minimumTabDragDistance;
+ (BOOL)useVirtualKeyCodesForDetectingDigits;
+ (BOOL)excludeBackgroundColorsFromCopiedStyle;
+ (BOOL)useGCDUpdateTimer;
+ (BOOL)fullHeightCursor;
+ (BOOL)drawOutlineAroundCursor;
+ (double)underlineCursorOffset;
+ (BOOL)logRestorableStateSize;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -161,7 +161,6 @@
 + (BOOL)useColorfgbgFallback;
 + (BOOL)promptForPasteWhenNotAtPrompt;
 + (void)setPromptForPasteWhenNotAtPrompt:(BOOL)value;
-+ (BOOL)performDNSLookups;
 + (BOOL)zeroWidthSpaceAdvancesCursor;
 + (BOOL)darkThemeHasBlackTitlebar;
 + (BOOL)fontChangeAffectsBroadcastingSessions;
```
