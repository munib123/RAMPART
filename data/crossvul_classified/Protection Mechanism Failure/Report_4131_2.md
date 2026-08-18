# CrossVul Fix Pair: Protection Mechanism Failure in c
**Pair ID:** 4131_2
**Vulnerability Class:** Protection Mechanism Failure
**CWE:** CWE-693
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4131_2`)

## Vulnerability Information & PoC

## Description
Protection Mechanism Failure - This weakness covers three distinct situations.

## Vulnerable Code
```c
Lines 1-28 of the vulnerable file.

// Copyright (c) 2018 GitHub, Inc.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

#ifndef SHELL_BROWSER_ELECTRON_NAVIGATION_THROTTLE_H_
#define SHELL_BROWSER_ELECTRON_NAVIGATION_THROTTLE_H_

#include "content/public/browser/navigation_throttle.h"

namespace electron {

class ElectronNavigationThrottle : public content::NavigationThrottle {
 public:
  explicit ElectronNavigationThrottle(content::NavigationHandle* handle);
  ~ElectronNavigationThrottle() override;

  ElectronNavigationThrottle::ThrottleCheckResult WillRedirectRequest()
      override;

  const char* GetNameForLogging() override;

 private:
  DISALLOW_COPY_AND_ASSIGN(ElectronNavigationThrottle);
};

}  // namespace electron

#endif  // SHELL_BROWSER_ELECTRON_NAVIGATION_THROTTLE_H_
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,6 +14,8 @@
   explicit ElectronNavigationThrottle(content::NavigationHandle* handle);
   ~ElectronNavigationThrottle() override;
 
+  ElectronNavigationThrottle::ThrottleCheckResult WillStartRequest() override;
+
   ElectronNavigationThrottle::ThrottleCheckResult WillRedirectRequest()
       override;
 
```
