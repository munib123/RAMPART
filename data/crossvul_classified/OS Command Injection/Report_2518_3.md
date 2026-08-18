# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in cpp
**Pair ID:** 2518_3
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2518_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```cpp
Lines 20-60 of the vulnerable file.

/* along with XRootD in a file called COPYING.LESSER (LGPL license) and file  */
/* COPYING (GPL license).  If not, see <http://www.gnu.org/licenses/>.        */
/*                                                                            */
/* The copyright holder's institutional names and contributor's names may not */
/* be used to endorse or promote products derived from this software without  */
/* specific prior written permission of the institution or contributor.       */
/*                                                                            */
/******************************************************************************/

#include "XrdVersion.hh"

/******************************************************************************/
/*                   V e r s i o n   I n f o r m a t i o n                    */
/******************************************************************************/
  
XrdVERSIONINFO(XrdSecgsiGMAPFun,secgsigmap);

/* ************************************************************************** */
/*                                                                            */
/* GMAP function implementation querying a LDAP database                      */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static char *ldapsrv    = 0;
static char *searchbase = 0;
static char *attribute  = 0;

int XrdSecgsiGMAPInit(const char *cfg);

//
// Main function
//
extern "C"
{
char *XrdSecgsiGMAPFun(const char *dn, int now)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,6 +37,15 @@
 /* ************************************************************************** */
 /*                                                                            */
 /* GMAP function implementation querying a LDAP database                      */
+/*                                                                            */
+/* Warning: this plug-in is not build any longer because the external         */
+/* LDAP query via the popen() represents a potential security threat          */
+/* and it is believed that functionality provided is not actually used.       */
+/* If this believe happens to be uncorrect please report at                   */
+/*                                                                            */
+/*                   https://github.com/xrootd                                */
+/*                                                                            */
+/* a sanitized version of the plug-in can be provided using a proper library. */
 /*                                                                            */
 /* ************************************************************************** */
 
```
