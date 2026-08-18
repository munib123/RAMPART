# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 3058_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3058_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 1061-1082 of the vulnerable file.

        }

        @Override
        public int getPriority() {
            // should always come first so that ID that are ids get mapped correctly
            return Integer.MAX_VALUE;
        }

    }

    /**
     * Jenkins now refuses to let the user login if he/she doesn't exist in {@link SecurityRealm},
     * which was necessary to make sure users removed from the backend will get removed from the frontend.
     * <p>
     * Unfortunately this infringed some legitimate use cases of creating Jenkins-local users for
     * automation purposes. This escape hatch switch can be enabled to resurrect that behaviour.
     *
     * JENKINS-22346.
     */
    public static boolean ALLOW_NON_EXISTENT_USER_TO_LOGIN = Boolean.getBoolean(User.class.getName()+".allowNonExistentUserToLogin");
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1078,5 +1078,22 @@
      * JENKINS-22346.
      */
     public static boolean ALLOW_NON_EXISTENT_USER_TO_LOGIN = Boolean.getBoolean(User.class.getName()+".allowNonExistentUserToLogin");
+
+
+    /**
+     * Jenkins historically created a (usually) ephemeral user record when an user with Overall/Administer permission
+     * accesses a /user/arbitraryName URL.
+     * <p>
+     * Unfortunately this constitutes a CSRF vulnerability, as malicious users can make admins create arbitrary numbers
+     * of ephemeral user records, so the behavior was changed in Jenkins 2.TODO / 2.32.2.
+     * <p>
+     * As some users may be relying on the previous behavior, setting this to true restores the previous behavior. This
+     * is not recommended.
+     *
+     * SECURITY-406.
+     */
+    // TODO 2.4+ SystemProperties
+    @Restricted(NoExternalUse.class)
+    public static boolean ALLOW_USER_CREATION_VIA_URL = Boolean.getBoolean(User.class.getName() + ".allowUserCreationViaUrl");
 }
 
```
