# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 1899_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1899_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 21-61 of the vulnerable file.

import org.yaml.snakeyaml.DumperOptions.FlowStyle;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.emitter.Emitter;
import org.yaml.snakeyaml.introspector.BeanAccess;
import org.yaml.snakeyaml.introspector.MethodProperty;
import org.yaml.snakeyaml.introspector.Property;
import org.yaml.snakeyaml.introspector.PropertyUtils;
import org.yaml.snakeyaml.nodes.MappingNode;
import org.yaml.snakeyaml.nodes.Node;
import org.yaml.snakeyaml.nodes.NodeTuple;
import org.yaml.snakeyaml.nodes.ScalarNode;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;
import org.yaml.snakeyaml.resolver.Resolver;
import org.yaml.snakeyaml.serializer.Serializer;

import edu.emory.mathcs.backport.java.util.Collections;
import io.onedev.commons.launcher.loader.ImplementationRegistry;
import io.onedev.commons.utils.ClassUtils;
import io.onedev.server.OneDev;
import io.onedev.server.GeneralException;
import io.onedev.server.util.BeanUtils;
import io.onedev.server.web.editable.annotation.Editable;

public class VersionedYamlDoc extends MappingNode {

	public VersionedYamlDoc(MappingNode wrapped) {
		super(wrapped.getTag(), wrapped.getValue(), wrapped.getFlowStyle());
	}
	
	public static VersionedYamlDoc fromYaml(String yaml) {
		return new VersionedYamlDoc((MappingNode) new OneYaml().compose(new StringReader(yaml)));
	}
	
	@SuppressWarnings("unchecked")
	public <T> T toBean(Class<T> beanClass) {
        setTag(new Tag(beanClass));
        
		if (getVersion() != null) {
			try {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,8 +38,8 @@
 import edu.emory.mathcs.backport.java.util.Collections;
 import io.onedev.commons.launcher.loader.ImplementationRegistry;
 import io.onedev.commons.utils.ClassUtils;
+import io.onedev.server.GeneralException;
 import io.onedev.server.OneDev;
-import io.onedev.server.GeneralException;
 import io.onedev.server.util.BeanUtils;
 import io.onedev.server.web.editable.annotation.Editable;
 
@@ -56,7 +56,6 @@
 	@SuppressWarnings("unchecked")
 	public <T> T toBean(Class<T> beanClass) {
         setTag(new Tag(beanClass));
-        
 		if (getVersion() != null) {
 			try {
 				MigrationHelper.migrate(getVersion(), beanClass.newInstance(), this);
@@ -131,17 +130,26 @@
 
 		@Override
 		protected Class<?> getClassForNode(Node node) {
-			Class<?> type = node.getType();
-			if (type.getAnnotation(Editable.class) != null && !ClassUtils.isConcrete(type)) {
-				ImplementationRegistry registry = OneDev.getInstance(ImplementationRegistry.class);
-				for (Class<?> implementationClass: registry.getImplementations(node.getType())) {
-					String implementationTag = new Tag("!" + implementationClass.getSimpleName()).getValue();
-					if (implementationTag.equals(node.getTag().getValue()))
-						return implementationClass;
+			if (node instanceof VersionedYamlDoc) {
+				return super.getClassForNode(node);
+			} else {
+				Class<?> type = node.getType();
+				if (type.getAnnotation(Editable.class) == null) {
+					// Do not deserialize unknown classes to avoid security vulnerabilities
+					throw new IllegalStateException(String.format("Unexpected yaml node (type: %s, tag: %s)", 
+							type, node.getTag()));
+				} else {
+					if (!ClassUtils.isConcrete(type)) {
+						ImplementationRegistry registry = OneDev.getInstance(ImplementationRegistry.class);
+						for (Class<?> implementationClass: registry.getImplementations(node.getType())) {
+							String implementationTag = new Tag("!" + implementationClass.getSimpleName()).getValue();
+							if (implementationTag.equals(node.getTag().getValue()))
+								return implementationClass;
+						}
+					}
+					return super.getClassForNode(node);
 				}
 			}
-			
-			return super.getClassForNode(node);
 		}
 		
 	}
```
