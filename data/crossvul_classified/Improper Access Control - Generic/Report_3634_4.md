# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3634_4
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3634_4`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 2796-2836 of the vulnerable file.

def security_group_destroy(context, security_group_id):
    session = get_session()
    with session.begin():
        session.query(models.SecurityGroup).\
                filter_by(id=security_group_id).\
                update({'deleted': True,
                        'deleted_at': utils.utcnow(),
                        'updated_at': literal_column('updated_at')})
        session.query(models.SecurityGroupInstanceAssociation).\
                filter_by(security_group_id=security_group_id).\
                update({'deleted': True,
                        'deleted_at': utils.utcnow(),
                        'updated_at': literal_column('updated_at')})
        session.query(models.SecurityGroupIngressRule).\
                filter_by(group_id=security_group_id).\
                update({'deleted': True,
                        'deleted_at': utils.utcnow(),
                        'updated_at': literal_column('updated_at')})


###################


def _security_group_rule_get_query(context, session=None):
    return model_query(context, models.SecurityGroupIngressRule,
                       session=session)


@require_context
def security_group_rule_get(context, security_group_rule_id, session=None):
    result = _security_group_rule_get_query(context, session=session).\
                         filter_by(id=security_group_rule_id).\
                         first()

    if not result:
        raise exception.SecurityGroupNotFoundForRule(
                                               rule_id=security_group_rule_id)

    return result


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2813,6 +2813,13 @@
                         'updated_at': literal_column('updated_at')})
 
 
+@require_context
+def security_group_count_by_project(context, project_id):
+    authorize_project_context(context, project_id)
+    return model_query(context, models.SecurityGroup, read_deleted="no").\
+                   filter_by(project_id=project_id).\
+                   count()
+
 ###################
 
 
@@ -2871,6 +2878,14 @@
         security_group_rule.delete(session=session)
 
 
+@require_context
+def security_group_rule_count_by_group(context, security_group_id):
+    return model_query(context, models.SecurityGroupIngressRule,
+                   read_deleted="no").\
+                   filter_by(parent_group_id=security_group_id).\
+                   count()
+
+#
 ###################
 
 
@@ -3018,6 +3033,7 @@
         user_ref.save(session=session)
 
 
+#
 ###################
 
 
```
