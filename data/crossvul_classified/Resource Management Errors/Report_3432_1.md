# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3432_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3432_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 507-547 of the vulnerable file.

ICALL_TYPE(ASSEMN, "System.Reflection.AssemblyName", ASSEMN_1)
ICALL(ASSEMN_1, "ParseName", ves_icall_System_Reflection_AssemblyName_ParseName)

ICALL_TYPE(CATTR_DATA, "System.Reflection.CustomAttributeData", CATTR_DATA_1)
ICALL(CATTR_DATA_1, "ResolveArgumentsInternal", mono_reflection_resolve_custom_attribute_data)

ICALL_TYPE(ASSEMB, "System.Reflection.Emit.AssemblyBuilder", ASSEMB_1)
ICALL(ASSEMB_1, "InternalAddModule", mono_image_load_module_dynamic)
ICALL(ASSEMB_2, "basic_init", mono_image_basic_init)

ICALL_TYPE(CATTRB, "System.Reflection.Emit.CustomAttributeBuilder", CATTRB_1)
ICALL(CATTRB_1, "GetBlob", mono_reflection_get_custom_attrs_blob)

#ifndef DISABLE_REFLECTION_EMIT
ICALL_TYPE(DERIVEDTYPE, "System.Reflection.Emit.DerivedType", DERIVEDTYPE_1)
ICALL(DERIVEDTYPE_1, "create_unmanaged_type", mono_reflection_create_unmanaged_type)
#endif

ICALL_TYPE(DYNM, "System.Reflection.Emit.DynamicMethod", DYNM_1)
ICALL(DYNM_1, "create_dynamic_method", mono_reflection_create_dynamic_method)
ICALL(DYNM_2, "destroy_dynamic_method", mono_reflection_destroy_dynamic_method)

ICALL_TYPE(ENUMB, "System.Reflection.Emit.EnumBuilder", ENUMB_1)
ICALL(ENUMB_1, "setup_enum_type", ves_icall_EnumBuilder_setup_enum_type)

ICALL_TYPE(GPARB, "System.Reflection.Emit.GenericTypeParameterBuilder", GPARB_1)
ICALL(GPARB_1, "initialize", mono_reflection_initialize_generic_parameter)

ICALL_TYPE(METHODB, "System.Reflection.Emit.MethodBuilder", METHODB_1)
ICALL(METHODB_1, "MakeGenericMethod", mono_reflection_bind_generic_method_parameters)

ICALL_TYPE(MODULEB, "System.Reflection.Emit.ModuleBuilder", MODULEB_8)
ICALL(MODULEB_8, "RegisterToken", ves_icall_ModuleBuilder_RegisterToken)
ICALL(MODULEB_1, "WriteToFile", ves_icall_ModuleBuilder_WriteToFile)
ICALL(MODULEB_2, "basic_init", mono_image_module_basic_init)
ICALL(MODULEB_3, "build_metadata", ves_icall_ModuleBuilder_build_metadata)
ICALL(MODULEB_4, "create_modified_type", ves_icall_ModuleBuilder_create_modified_type)
ICALL(MODULEB_5, "getMethodToken", ves_icall_ModuleBuilder_getMethodToken)
ICALL(MODULEB_6, "getToken", ves_icall_ModuleBuilder_getToken)
ICALL(MODULEB_7, "getUSIndex", mono_image_insert_string)
ICALL(MODULEB_9, "set_wrappers_type", mono_image_set_wrappers_type)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -524,7 +524,6 @@
 
 ICALL_TYPE(DYNM, "System.Reflection.Emit.DynamicMethod", DYNM_1)
 ICALL(DYNM_1, "create_dynamic_method", mono_reflection_create_dynamic_method)
-ICALL(DYNM_2, "destroy_dynamic_method", mono_reflection_destroy_dynamic_method)
 
 ICALL_TYPE(ENUMB, "System.Reflection.Emit.EnumBuilder", ENUMB_1)
 ICALL(ENUMB_1, "setup_enum_type", ves_icall_EnumBuilder_setup_enum_type)
```
