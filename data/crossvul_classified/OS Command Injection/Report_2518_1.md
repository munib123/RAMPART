# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in cpp
**Pair ID:** 2518_1
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2518_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```cpp
Lines 653-693 of the vulnerable file.

    sFileTimer     = new FileTimer();
    sPlugInManager = new PlugInManager();

    sPlugInManager->ProcessEnvironmentSettings();
    sForkHandler->RegisterFileTimer( sFileTimer );

    //--------------------------------------------------------------------------
    // MacOSX library loading is completely moronic. We cannot dlopen a library
    // from a thread other than a main thread, so we-pre dlopen all the
    // libraries that we may potentially want.
    //--------------------------------------------------------------------------
#ifdef __APPLE__
    char *errBuff = new char[1024];

    const char *libs[] =
    {
      "libXrdSeckrb5.so",
      "libXrdSecgsi.so",
      "libXrdSecgsiAuthzVO.so",
      "libXrdSecgsiGMAPDN.so",
      "libXrdSecgsiGMAPLDAP.so",
      "libXrdSecpwd.so",
      "libXrdSecsss.so",
      "libXrdSecunix.so",
      0
    };

    for( int i = 0; libs[i]; ++i )
    {
      sLog->Debug( UtilityMsg, "Attempting to pre-load: %s", libs[i] );
      bool ok = XrdOucPreload( libs[i], errBuff, 1024 );
      if( !ok )
        sLog->Error( UtilityMsg, "Unable to pre-load %s: %s", libs[i], errBuff );
    }
    delete [] errBuff;
#endif
  }

  //----------------------------------------------------------------------------
  // Finalize the environment
  //----------------------------------------------------------------------------
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -670,7 +670,6 @@
       "libXrdSecgsi.so",
       "libXrdSecgsiAuthzVO.so",
       "libXrdSecgsiGMAPDN.so",
-      "libXrdSecgsiGMAPLDAP.so",
       "libXrdSecpwd.so",
       "libXrdSecsss.so",
       "libXrdSecunix.so",
```
