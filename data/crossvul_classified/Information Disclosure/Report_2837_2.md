# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in python
**Pair ID:** 2837_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2837_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```python
Lines 796-836 of the vulnerable file.

    'experimental test code used during development'

    uri = 'https://openstack.jdennis.oslab.test:5000/v3/mellon/fooResponse'

    conn.remove_client_by_name_redirect_uri(options.realm_name,
                                            options.client_name,
                                            uri)

# ------------------------------------------------------------------------------

verbose_help = '''

The structure of the command line arguments is "noun verb" where noun
is one of Keycloak's data items (e.g. realm, client, etc.) and the
verb is an action to perform on the item. Each of the nouns and verbs
may have their own set of arguments which must follow the noun or
verb.

For example to delete the client XYZ in the realm ABC:

{prog_name} -s http://example.com:8080 -p password client delete -r ABC -c XYZ

where 'client' is the noun, 'delete' is the verb and -r ABC -c XYZ are
arguments to the delete action.

If the command completes successfully the exit status is 0. The exit
status is 1 if an authenticated connection with the server cannont be
successfully established. The exit status is 2 if the REST operation
fails.

The server should be a scheme://hostname:port URL.
'''


class TlsVerifyAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not allowed")
        super(TlsVerifyAction, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -813,7 +813,7 @@
 
 For example to delete the client XYZ in the realm ABC:
 
-{prog_name} -s http://example.com:8080 -p password client delete -r ABC -c XYZ
+echo password | {prog_name} -s http://example.com:8080 -P - client delete -r ABC -c XYZ
 
 where 'client' is the noun, 'delete' is the verb and -r ABC -c XYZ are
 arguments to the delete action.
@@ -895,9 +895,11 @@
                        default='admin',
                        help='admin user name (default: admin)')
 
-    group.add_argument('-p', '--admin-password',
-                       required=True,
-                       help='admin password')
+    group.add_argument('-P', '--admin-password-file',
+                       type=argparse.FileType('rb'),
+                       help=('file containing admin password '
+                             '(or use a hyphen "-" to read the password '
+                             'from stdin)'))
 
     group.add_argument('--admin-realm',
                        default='master',
@@ -994,6 +996,20 @@
 
     if options.permit_insecure_transport:
         os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
+
+    # Get admin password
+    options.admin_password = None
+
+    # 1. Try password file
+    if options.admin_password_file is not None:
+        options.admin_password = options.keycloak_admin_password_file.readline().strip()
+        options.keycloak_admin_password_file.close()
+
+    # 2. Try KEYCLOAK_ADMIN_PASSWORD environment variable
+    if options.admin_password is None:
+        if (('KEYCLOAK_ADMIN_PASSWORD' in os.environ) and
+            (os.environ['KEYCLOAK_ADMIN_PASSWORD'])):
+            options.admin_password = os.environ['KEYCLOAK_ADMIN_PASSWORD']
 
     try:
         anonymous_conn = KeycloakAnonymousConnection(options.server,
```
