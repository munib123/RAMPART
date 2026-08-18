# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3633_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3633_3`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 1081-1121 of the vulnerable file.

def security_group_exists(context, project_id, group_name):
    """Indicates if a group name exists in a project."""
    return IMPL.security_group_exists(context, project_id, group_name)


def security_group_create(context, values):
    """Create a new security group."""
    return IMPL.security_group_create(context, values)


def security_group_destroy(context, security_group_id):
    """Deletes a security group."""
    return IMPL.security_group_destroy(context, security_group_id)


def security_group_destroy_all(context):
    """Deletes a security group."""
    return IMPL.security_group_destroy_all(context)


####################


def security_group_rule_create(context, values):
    """Create a new security group."""
    return IMPL.security_group_rule_create(context, values)


def security_group_rule_get_by_security_group(context, security_group_id):
    """Get all rules for a a given security group."""
    return IMPL.security_group_rule_get_by_security_group(context,
                                                          security_group_id)


def security_group_rule_get_by_security_group_grantee(context,
                                                      security_group_id):
    """Get all rules that grant access to the given security group."""
    return IMPL.security_group_rule_get_by_security_group_grantee(context,
                                                             security_group_id)


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1098,6 +1098,11 @@
     return IMPL.security_group_destroy_all(context)
 
 
+def security_group_count_by_project(context, project_id):
+    """Count number of security groups in a project."""
+    return IMPL.security_group_count_by_project(context, project_id)
+
+
 ####################
 
 
@@ -1127,6 +1132,11 @@
 def security_group_rule_get(context, security_group_rule_id):
     """Gets a security group rule."""
     return IMPL.security_group_rule_get(context, security_group_rule_id)
+
+
+def security_group_rule_count_by_group(context, security_group_id):
+    """Count rules in a given security group."""
+    return IMPL.security_group_rule_count_by_group(context, security_group_id)
 
 
 ###################
```
