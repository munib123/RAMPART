# CrossVul Fix Pair: Resource Management Errors in csharp
**Pair ID:** 3432_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3432_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```csharp
Lines 110-152 of the vulnerable file.

					if (parameterTypes [i] == null)
						throw new ArgumentException ("Parameter " + i + " is null", "parameterTypes");
			}

			if (m == null)
				m = AnonHostModuleHolder.anon_host_module;

			this.name = name;
			this.attributes = attributes | MethodAttributes.Static;
			this.callingConvention = callingConvention;
			this.returnType = returnType;
			this.parameters = parameterTypes;
			this.owner = owner;
			this.module = m;
			this.skipVisibility = skipVisibility;
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		private extern void create_dynamic_method (DynamicMethod m);

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		private extern void destroy_dynamic_method (DynamicMethod m);

		private void CreateDynMethod () {
			if (mhandle.Value == IntPtr.Zero) {
				if (ilgen == null || ilgen.ILOffset == 0)
					throw new InvalidOperationException ("Method '" + name + "' does not have a method body.");

				ilgen.label_fixup ();

				// Have to create all DynamicMethods referenced by this one
				try {
					// Used to avoid cycles
					creating = true;
					if (refs != null) {
						for (int i = 0; i < refs.Length; ++i) {
							if (refs [i] is DynamicMethod) {
								DynamicMethod m = (DynamicMethod)refs [i];
								if (!m.creating)
									m.CreateDynMethod ();
							}
						}
					}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -127,9 +127,6 @@
 		[MethodImplAttribute(MethodImplOptions.InternalCall)]
 		private extern void create_dynamic_method (DynamicMethod m);
 
-		[MethodImplAttribute(MethodImplOptions.InternalCall)]
-		private extern void destroy_dynamic_method (DynamicMethod m);
-
 		private void CreateDynMethod () {
 			if (mhandle.Value == IntPtr.Zero) {
 				if (ilgen == null || ilgen.ILOffset == 0)
@@ -158,11 +155,6 @@
 			}
 		}
 
-		~DynamicMethod ()
-		{
-			destroy_dynamic_method (this);
-		}
-
 		[ComVisible (true)]
 		public Delegate CreateDelegate (Type delegateType)
 		{
```
