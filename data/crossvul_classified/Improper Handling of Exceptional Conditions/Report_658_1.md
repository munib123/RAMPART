# CrossVul Fix Pair: Improper Handling of Exceptional Conditions in java
**Pair ID:** 658_1
**Vulnerability Class:** Improper Handling of Exceptional Conditions
**CWE:** CWE-755
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `658_1`)

## Vulnerability Information & PoC

## Description
Improper Handling of Exceptional Conditions - The product does not handle or incorrectly handles an exceptional condition.

## Vulnerable Code
```java
Lines 165-205 of the vulnerable file.

            .getHostnameVerifier(tlsClientParameters);

        if (connection instanceof HttpsURLConnection) {
            // handle the expected case (javax.net.ssl)
            HttpsURLConnection conn = (HttpsURLConnection) connection;
            conn.setHostnameVerifier(verifier);
            conn.setSSLSocketFactory(socketFactory);
        } else {
            // handle the deprecated sun case and other possible hidden API's
            // that are similar to the Sun cases
            try {
                Method method = connection.getClass().getMethod("getHostnameVerifier");

                InvocationHandler handler = new ReflectionInvokationHandler(verifier) {
                    public Object invoke(Object proxy,
                                         Method method,
                                         Object[] args) throws Throwable {
                        try {
                            return super.invoke(proxy, method, args);
                        } catch (Exception ex) {
                            return true;
                        }
                    }
                };
                Object proxy = java.lang.reflect.Proxy.newProxyInstance(this.getClass().getClassLoader(),
                                                                        new Class[] {method.getReturnType()},
                                                                        handler);

                method = connection.getClass().getMethod("setHostnameVerifier", method.getReturnType());
                method.invoke(connection, proxy);
            } catch (Exception ex) {
                //Ignore this one
            }
            try {
                Method getSSLSocketFactory = connection.getClass().getMethod("getSSLSocketFactory");
                Method setSSLSocketFactory = connection.getClass()
                    .getMethod("setSSLSocketFactory", getSSLSocketFactory.getReturnType());
                if (getSSLSocketFactory.getReturnType().isInstance(socketFactory)) {
                    setSSLSocketFactory.invoke(connection, socketFactory);
                } else {
                    //need to see if we can create one - mostly the weblogic case.   The
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -182,7 +182,7 @@
                         try {
                             return super.invoke(proxy, method, args);
                         } catch (Exception ex) {
-                            return true;
+                            return false;
                         }
                     }
                 };
```
