# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 3470_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3470_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 24-64 of the vulnerable file.

#include "utils.h"
#include "npw-common.h"

#define DEBUG 1
#include "debug.h"


/*
 *  RPC types of NPP/NPN variables
 */

int rpc_type_of_NPNVariable(int variable)
{
  int type;
  switch (variable) {
  case NPNVjavascriptEnabledBool:
  case NPNVasdEnabledBool:
  case NPNVisOfflineBool:
  case NPNVSupportsXEmbedBool:
  case NPNVSupportsWindowless:
	type = RPC_TYPE_BOOLEAN;
	break;
  case NPNVToolkit:
  case NPNVnetscapeWindow:
	type = RPC_TYPE_UINT32;
	break;
  case NPNVWindowNPObject:
  case NPNVPluginElementNPObject:
	type = RPC_TYPE_NP_OBJECT;
	break;
  default:
	type = RPC_ERROR_GENERIC;
	break;
  }
  return type;
}

int rpc_type_of_NPPVariable(int variable)
{
  int type;
  switch (variable) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,6 +41,8 @@
   case NPNVisOfflineBool:
   case NPNVSupportsXEmbedBool:
   case NPNVSupportsWindowless:
+  case NPNVprivateModeBool:
+  case NPNVsupportsAdvancedKeyHandling:
 	type = RPC_TYPE_BOOLEAN;
 	break;
   case NPNVToolkit:
@@ -65,6 +67,7 @@
   case NPPVpluginNameString:
   case NPPVpluginDescriptionString:
   case NPPVformValue: // byte values of 0 does not appear in the UTF-8 encoding but for U+0000
+  case NPPVpluginNativeAccessibleAtkPlugId:
 	type = RPC_TYPE_STRING;
 	break;
   case NPPVpluginWindowSize:
@@ -76,6 +79,10 @@
   case NPPVpluginTransparentBool:
   case NPPVjavascriptPushCallerBool:
   case NPPVpluginKeepLibraryInMemory:
+  case NPPVpluginUrlRequestsDisplayedBool:
+  case NPPVpluginWantsAllNetworkStreams:
+  case NPPVpluginCancelSrcStream:
+  case NPPVSupportsAdvancedKeyHandling:
 	type = RPC_TYPE_BOOLEAN;
 	break;
   case NPPVpluginScriptableNPObject:
```
