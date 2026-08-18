# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in cpp
**Pair ID:** 3258_2
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3258_2`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```cpp
Lines 34-74 of the vulnerable file.


using namespace rfb;

static LogWriter vlog("SConnection");

// AccessRights values
const SConnection::AccessRights SConnection::AccessView           = 0x0001;
const SConnection::AccessRights SConnection::AccessKeyEvents      = 0x0002;
const SConnection::AccessRights SConnection::AccessPtrEvents      = 0x0004;
const SConnection::AccessRights SConnection::AccessCutText        = 0x0008;
const SConnection::AccessRights SConnection::AccessSetDesktopSize = 0x0010;
const SConnection::AccessRights SConnection::AccessNonShared      = 0x0020;
const SConnection::AccessRights SConnection::AccessDefault        = 0x03ff;
const SConnection::AccessRights SConnection::AccessNoQuery        = 0x0400;
const SConnection::AccessRights SConnection::AccessFull           = 0xffff;


SConnection::SConnection()
  : readyForSetColourMapEntries(false),
    is(0), os(0), reader_(0), writer_(0),
    security(0), ssecurity(0), state_(RFBSTATE_UNINITIALISED),
    preferredEncoding(encodingRaw)
{
  defaultMajorVersion = 3;
  defaultMinorVersion = 8;
  if (rfb::Server::protocol3_3)
    defaultMinorVersion = 3;

  cp.setVersion(defaultMajorVersion, defaultMinorVersion);

  security = new SecurityServer();
}

SConnection::~SConnection()
{
  if (ssecurity) ssecurity->destroy();
  delete reader_;
  reader_ = 0;
  delete writer_;
  writer_ = 0;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -51,7 +51,7 @@
 SConnection::SConnection()
   : readyForSetColourMapEntries(false),
     is(0), os(0), reader_(0), writer_(0),
-    security(0), ssecurity(0), state_(RFBSTATE_UNINITIALISED),
+    ssecurity(0), state_(RFBSTATE_UNINITIALISED),
     preferredEncoding(encodingRaw)
 {
   defaultMajorVersion = 3;
@@ -60,8 +60,6 @@
     defaultMinorVersion = 3;
 
   cp.setVersion(defaultMajorVersion, defaultMinorVersion);
-
-  security = new SecurityServer();
 }
 
 SConnection::~SConnection()
@@ -142,7 +140,7 @@
 
   std::list<rdr::U8> secTypes;
   std::list<rdr::U8>::iterator i;
-  secTypes = security->GetEnabledSecTypes();
+  secTypes = security.GetEnabledSecTypes();
 
   if (cp.isVersion(3,3)) {
 
@@ -161,7 +159,7 @@
     os->writeU32(*i);
     if (*i == secTypeNone) os->flush();
     state_ = RFBSTATE_SECURITY;
-    ssecurity = security->GetSSecurity(*i);
+    ssecurity = security.GetSSecurity(*i);
     processSecurityMsg();
     return;
   }
@@ -193,7 +191,7 @@
   std::list<rdr::U8> secTypes;
   std::list<rdr::U8>::iterator i;
 
-  secTypes = security->GetEnabledSecTypes();
+  secTypes = security.GetEnabledSecTypes();
   for (i=secTypes.begin(); i!=secTypes.end(); i++)
     if (*i == secType) break;
   if (i == secTypes.end())
@@ -204,7 +202,7 @@
 
   try {
     state_ = RFBSTATE_SECURITY;
-    ssecurity = security->GetSSecurity(secType);
+    ssecurity = security.GetSSecurity(secType);
   } catch (rdr::Exception& e) {
     throwConnFailedException(e.str());
   }
```
