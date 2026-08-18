# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in java
**Pair ID:** 4334_1
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4334_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```java
Lines 625-665 of the vulnerable file.

            .lookupMapperOfType(AttributeAliasingMapper.class);
        systemAttributeAliasingMapper = (SystemAttributeAliasingMapper)this.mapper
            .lookupMapperOfType(SystemAttributeAliasingMapper.class);
        implicitCollectionMapper = (ImplicitCollectionMapper)this.mapper
            .lookupMapperOfType(ImplicitCollectionMapper.class);
        defaultImplementationsMapper = (DefaultImplementationsMapper)this.mapper
            .lookupMapperOfType(DefaultImplementationsMapper.class);
        immutableTypesMapper = (ImmutableTypesMapper)this.mapper.lookupMapperOfType(ImmutableTypesMapper.class);
        localConversionMapper = (LocalConversionMapper)this.mapper.lookupMapperOfType(LocalConversionMapper.class);
        securityMapper = (SecurityMapper)this.mapper.lookupMapperOfType(SecurityMapper.class);
        annotationConfiguration = (AnnotationConfiguration)this.mapper
            .lookupMapperOfType(AnnotationConfiguration.class);
    }

    protected void setupSecurity() {
        if (securityMapper == null) {
            return;
        }

        addPermission(AnyTypePermission.ANY);
        denyTypes(new String[]{"java.beans.EventHandler"});
        denyTypesByRegExp(new Pattern[]{LAZY_ITERATORS, JAVAX_CRYPTO});
        allowTypeHierarchy(Exception.class);
        securityInitialized = false;
    }

    /**
     * Setup the security framework of a XStream instance.
     * <p>
     * This method is a pure helper method for XStream 1.4.x. It initializes an XStream instance with a white list of
     * well-known and simply types of the Java runtime as it is done in XStream 1.5.x by default. This method will do
     * therefore nothing in XStream 1.5.
     * </p>
     * 
     * @param xstream
     * @since 1.4.10
     */
    public static void setupDefaultSecurity(final XStream xstream) {
        if (!xstream.securityInitialized) {
            xstream.addPermission(NoTypePermission.NONE);
            xstream.addPermission(NullPermission.NULL);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -642,7 +642,7 @@
         }
 
         addPermission(AnyTypePermission.ANY);
-        denyTypes(new String[]{"java.beans.EventHandler"});
+        denyTypes(new String[]{"java.beans.EventHandler", "javax.imageio.ImageIO$ContainsFilter"});
         denyTypesByRegExp(new Pattern[]{LAZY_ITERATORS, JAVAX_CRYPTO});
         allowTypeHierarchy(Exception.class);
         securityInitialized = false;
```
