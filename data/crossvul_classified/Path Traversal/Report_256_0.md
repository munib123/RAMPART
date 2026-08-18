# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in java
**Pair ID:** 256_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `256_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```java
Lines 271-311 of the vulnerable file.

        }

        // Step 4. Use javax.faces.NamingContainer as the component type
        if (result == null) {
            result = app.createComponent("javax.faces.NamingContainer");
        }

        result.setRendererType("javax.faces.Composite");

        Map<String, Object> attrs = result.getAttributes();
        attrs.put(COMPONENT_RESOURCE_KEY, componentResource);
        attrs.put(BEANINFO_KEY, componentMetadata);

        associate.getAnnotationManager().applyComponentAnnotations(context, result);
        pushDeclaredDefaultValuesToAttributesMap(context, componentMetadata, attrs, result, expressionFactory);

        return result;
    }
    
    public UIComponent createComponent(FacesContext context, String componentType, String rendererType) {
        return createComponentApplyAnnotations(context, componentType, rendererType, true);
    }
    
    public UIComponent createComponent(ValueExpression componentExpression, FacesContext context, String componentType, String rendererType) {

        notNull(COMPONENT_EXPRESSION, componentExpression);
        notNull(CONTEXT, context);
        notNull(COMPONENT_TYPE, componentType);

        return createComponentApplyAnnotations(context, componentExpression, componentType, rendererType, true);
    }
    
    public UIComponent createComponent(ValueBinding componentBinding, FacesContext context, String componentType) throws FacesException {

        notNull("componentBinding", componentBinding);
        notNull(CONTEXT, context);
        notNull(COMPONENT_TYPE, componentType);

        Object result;
        boolean createOne = false;
        try {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -288,6 +288,10 @@
     }
     
     public UIComponent createComponent(FacesContext context, String componentType, String rendererType) {
+        
+        notNull(CONTEXT, context);
+        notNull(COMPONENT_TYPE, componentType);
+        
         return createComponentApplyAnnotations(context, componentType, rendererType, true);
     }
     
```
