# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 280_1
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `280_1`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 50-90 of the vulnerable file.

        Set<String> s = new HashSet<String>();
        // Courtesy of [https://github.com/kantega/notsoserial]:
        // (and wrt [databind#1599])
        s.add("org.apache.commons.collections.functors.InvokerTransformer");
        s.add("org.apache.commons.collections.functors.InstantiateTransformer");
        s.add("org.apache.commons.collections4.functors.InvokerTransformer");
        s.add("org.apache.commons.collections4.functors.InstantiateTransformer");
        s.add("org.codehaus.groovy.runtime.ConvertedClosure");
        s.add("org.codehaus.groovy.runtime.MethodClosure");
        s.add("org.springframework.beans.factory.ObjectFactory");
        s.add("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");

        // [databind#1737]; JDK provided
        s.add("java.util.logging.FileHandler");
        s.add("java.rmi.server.UnicastRemoteObject");
        // [databind#1737]; 3rd party
        s.add("org.springframework.aop.support.AbstractBeanFactoryPointcutAdvisor");
        s.add("org.springframework.beans.factory.config.PropertyPathFactoryBean");
        s.add("com.mchange.v2.c3p0.JndiRefForwardingDataSource");
        s.add("com.mchange.v2.c3p0.WrapperConnectionPoolDataSource");

        DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);
    }

    /**
     * Set of class names of types that are never to be deserialized.
     */
    private Set<String> _cfgIllegalClassNames = DEFAULT_NO_DESER_CLASS_NAMES;

    /*
    /**********************************************************
    /* Life-cycle
    /**********************************************************
     */
    
    /**
     * Globally shareable thread-safe instance which has no additional custom deserializers
     * registered
     */
    public final static BeanDeserializerFactory instance = new BeanDeserializerFactory(
            new DeserializerFactoryConfig());
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -67,6 +67,12 @@
         s.add("org.springframework.beans.factory.config.PropertyPathFactoryBean");
         s.add("com.mchange.v2.c3p0.JndiRefForwardingDataSource");
         s.add("com.mchange.v2.c3p0.WrapperConnectionPoolDataSource");
+
+        // [databind#2097]: some 3rd party, one JDK-bundled
+        s.add("org.slf4j.ext.EventData");
+        s.add("flex.messaging.util.concurrent.AsynchBeansWorkManagerExecutor");
+        s.add("com.sun.deploy.security.ruleset.DRSHelper");
+        s.add("org.apache.axis2.jaxws.spi.handler.HandlerResolverImpl");
 
         DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);
     }
```
