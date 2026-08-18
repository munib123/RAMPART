# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in cpp
**Pair ID:** 3258_0
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3258_0`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```cpp
Lines 27-67 of the vulnerable file.

#include <rfb/Security.h>
#include <rfb/SecurityClient.h>
#include <rfb/CConnection.h>
#include <rfb/util.h>

#include <rfb/LogWriter.h>

#include <rdr/InStream.h>
#include <rdr/OutStream.h>

using namespace rfb;

static LogWriter vlog("CConnection");

CConnection::CConnection()
  : csecurity(0), is(0), os(0), reader_(0), writer_(0),
    shared(false),
    state_(RFBSTATE_UNINITIALISED), useProtocol3_3(false),
    framebuffer(NULL), decoder(this)
{
  security = new SecurityClient();
}

CConnection::~CConnection()
{
  setFramebuffer(NULL);
  if (csecurity) csecurity->destroy();
  delete reader_;
  reader_ = 0;
  delete writer_;
  writer_ = 0;
}

void CConnection::setStreams(rdr::InStream* is_, rdr::OutStream* os_)
{
  is = is_;
  os = os_;
}

void CConnection::setFramebuffer(ModifiablePixelBuffer* fb)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,7 +44,6 @@
     state_(RFBSTATE_UNINITIALISED), useProtocol3_3(false),
     framebuffer(NULL), decoder(this)
 {
-  security = new SecurityClient();
 }
 
 CConnection::~CConnection()
@@ -167,7 +166,7 @@
   int secType = secTypeInvalid;
 
   std::list<rdr::U8> secTypes;
-  secTypes = security->GetEnabledSecTypes();
+  secTypes = security.GetEnabledSecTypes();
 
   if (cp.isVersion(3,3)) {
 
@@ -235,7 +234,7 @@
   }
 
   state_ = RFBSTATE_SECURITY;
-  csecurity = security->GetCSecurity(secType);
+  csecurity = security.GetCSecurity(secType);
   processSecurityMsg();
 }
 
```
