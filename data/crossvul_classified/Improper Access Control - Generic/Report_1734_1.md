# CrossVul Fix Pair: Improper Access Control in python
**Pair ID:** 1734_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1734_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```python
Lines 115-162 of the vulnerable file.


    security.declarePublic('testPropertiesValidity')
    def testPropertiesValidity(self, new_properties, member=None):
        '''If the properties are valid, returns None.  If not, returns
        a string explaining why.
        '''
        return None

    security.declarePublic('generatePassword')
    def generatePassword(self):
        """ Generate a valid password.
        """
        # we don't use these to avoid typos: OQ0Il1
        chars = 'ABCDEFGHJKLMNPRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
        return ''.join( [ choice(chars) for i in range(6) ] )

    security.declareProtected(AddPortalMember, 'addMember')
    @postonly
    def addMember(self, id, password, roles=('Member',), domains='',
                  properties=None, REQUEST=None):
        '''Creates a PortalMember and returns it. The properties argument
        can be a mapping with additional member properties. Raises an
        exception if the given id already exists, the password does not
        comply with the policy in effect, or the authenticated user is not
        allowed to grant one of the roles listed (where Member is a special
        role that can always be granted); these conditions should be
        detected before the fact so that a cleaner message can be printed.
        '''
        if not self.isMemberIdAllowed(id):
            raise ValueError(_(u'The login name you selected is already in '
                               u'use or is not valid. Please choose another.'))

        failMessage = self.testPasswordValidity(password)
        if failMessage is not None:
            raise ValueError(failMessage)

        if properties is not None:
            failMessage = self.testPropertiesValidity(properties)
            if failMessage is not None:
                raise ValueError(failMessage)

        # Limit the granted roles.
        # Anyone is always allowed to grant the 'Member' role.
        _limitGrantedRoles(roles, self, ('Member',))

        mtool = getUtility(IMembershipTool)
        mtool.addMember(id, password, roles, domains, properties)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -132,14 +132,17 @@
     @postonly
     def addMember(self, id, password, roles=('Member',), domains='',
                   properties=None, REQUEST=None):
-        '''Creates a PortalMember and returns it. The properties argument
-        can be a mapping with additional member properties. Raises an
-        exception if the given id already exists, the password does not
-        comply with the policy in effect, or the authenticated user is not
-        allowed to grant one of the roles listed (where Member is a special
-        role that can always be granted); these conditions should be
-        detected before the fact so that a cleaner message can be printed.
-        '''
+        # XXX Do not make this a normal method comment. Doing so makes
+        # this method publishable
+
+        # Creates a PortalMember and returns it. The properties argument
+        # can be a mapping with additional member properties. Raises an
+        # exception if the given id already exists, the password does not
+        # comply with the policy in effect, or the authenticated user is not
+        # allowed to grant one of the roles listed (where Member is a special
+        # role that can always be granted); these conditions should be
+        # detected before the fact so that a cleaner message can be printed.
+
         if not self.isMemberIdAllowed(id):
             raise ValueError(_(u'The login name you selected is already in '
                                u'use or is not valid. Please choose another.'))
```
