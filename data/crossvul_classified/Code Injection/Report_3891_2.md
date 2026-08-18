# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 3891_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3891_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 14-54 of the vulnerable file.

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;

/**
 * This class is the base validator for the <code>@SelfValidating</code> annotation. It
 * initiates the self validation process on an object, generating wrapping methods to call
 * the validation methods efficiently and then calls them.
 */
public class SelfValidatingValidator implements ConstraintValidator<SelfValidating, Object> {
    private static final Logger log = LoggerFactory.getLogger(SelfValidatingValidator.class);

    @SuppressWarnings("rawtypes")
    private final ConcurrentMap<Class<?>, List<ValidationCaller>> methodMap = new ConcurrentHashMap<>();
    private final AnnotationConfiguration annotationConfiguration = new AnnotationConfiguration.StdConfiguration(AnnotationInclusion.INCLUDE_AND_INHERIT_IF_INHERITED);
    private final TypeResolver typeResolver = new TypeResolver();
    private final MemberResolver memberResolver = new MemberResolver(typeResolver);

    @Override
    public void initialize(SelfValidating constraintAnnotation) {
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Override
    public boolean isValid(Object value, ConstraintValidatorContext context) {
        final ViolationCollector collector = new ViolationCollector(context);
        context.disableDefaultConstraintViolation();
        for (ValidationCaller caller : methodMap.computeIfAbsent(value.getClass(), this::findMethods)) {
            caller.setValidationObject(value);
            caller.call(collector);
        }
        return !collector.hasViolationOccurred();
    }

    /**
     * This method generates <code>ValidationCaller</code>s for each method annotated
     * with <code>@SelfValidation</code> that adheres to required signature.
     */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,15 +31,17 @@
     private final AnnotationConfiguration annotationConfiguration = new AnnotationConfiguration.StdConfiguration(AnnotationInclusion.INCLUDE_AND_INHERIT_IF_INHERITED);
     private final TypeResolver typeResolver = new TypeResolver();
     private final MemberResolver memberResolver = new MemberResolver(typeResolver);
+    private boolean escapeExpressions = true;
 
     @Override
     public void initialize(SelfValidating constraintAnnotation) {
+        escapeExpressions = constraintAnnotation.escapeExpressions();
     }
 
     @SuppressWarnings({"unchecked", "rawtypes"})
     @Override
     public boolean isValid(Object value, ConstraintValidatorContext context) {
-        final ViolationCollector collector = new ViolationCollector(context);
+        final ViolationCollector collector = new ViolationCollector(context, escapeExpressions);
         context.disableDefaultConstraintViolation();
         for (ValidationCaller caller : methodMap.computeIfAbsent(value.getClass(), this::findMethods)) {
             caller.setValidationObject(value);
```
