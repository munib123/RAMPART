# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3633_4
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3633_4`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 2786-2826 of the vulnerable file.

                update({'deleted': True,
                        'deleted_at': utils.utcnow(),
                        'updated_at': literal_column('updated_at')})


@require_context
def security_group_destroy_all(context, session=None):
    if not session:
        session = get_session()
    with session.begin():
        session.query(models.SecurityGroup).\
                update({'deleted': True,
                        'deleted_at': utils.utcnow(),
                        'updated_at': literal_column('updated_at')})
        session.query(models.SecurityGroupIngressRule).\
                update({'deleted': True,
                        'deleted_at': utils.utcnow(),
                        'updated_at': literal_column('updated_at')})


###################


@require_context
def security_group_rule_get(context, security_group_rule_id, session=None):
    if not session:
        session = get_session()
    if is_admin_context(context):
        result = session.query(models.SecurityGroupIngressRule).\
                         filter_by(deleted=can_read_deleted(context)).\
                         filter_by(id=security_group_rule_id).\
                         first()
    else:
        # TODO(vish): Join to group and check for project_id
        result = session.query(models.SecurityGroupIngressRule).\
                         filter_by(deleted=False).\
                         filter_by(id=security_group_rule_id).\
                         first()
    if not result:
        raise exception.SecurityGroupNotFoundForRule(
                                               rule_id=security_group_rule_id)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2803,6 +2803,16 @@
                         'updated_at': literal_column('updated_at')})
 
 
+@require_context
+def security_group_count_by_project(context, project_id):
+    authorize_project_context(context, project_id)
+    session = get_session()
+    return session.query(models.SecurityGroup).\
+                         filter_by(deleted=False).\
+                         filter_by(project_id=project_id).\
+                         count()
+
+
 ###################
 
 
@@ -2882,6 +2892,15 @@
                                                       security_group_rule_id,
                                                       session=session)
         security_group_rule.delete(session=session)
+
+
+@require_context
+def security_group_rule_count_by_group(context, security_group_id):
+    session = get_session()
+    return session.query(models.SecurityGroupIngressRule).\
+                         filter_by(deleted=False).\
+                         filter_by(parent_group_id=security_group_id).\
+                         count()
 
 
 ###################
```
