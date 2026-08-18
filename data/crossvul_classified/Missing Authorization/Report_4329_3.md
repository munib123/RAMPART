# CrossVul Fix Pair: Missing Authorization in php
**Pair ID:** 4329_3
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4329_3`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 390-431 of the vulnerable file.

            (int)$xpath->evaluate('count(' . $result_path . '/d:propstat/d:prop/d:resourcetype/child::node())')
         )->isEqualTo(count($resourcetypes));
         $child_index = 1;
         foreach ($resourcetypes as $resourcetype) {
            $this->integer(
               (int)$xpath->evaluate('count(' . $result_path . '/d:propstat/d:prop/d:resourcetype/' . $resourcetype . ')')
            )->isEqualTo(1);
            $child_index++;
         }

         $response_index++;
      }
   }

   /**
    * Test PROPFIND method on calendar endpoints.
    * Tests validates that mandatory properties are correctly set.
    */
   public function testPropfindOnPrincipalCalendar() {

      $login = TU_USER;
      $pass  = TU_PASS;
      $user  = getItemByTypeName('User', $login);

      $this->login($login, $pass);

      $group = new \Group();
      $group_id = (int)$group->add([
         'name' => 'Test group'
      ]);
      $this->integer($group_id)->isGreaterThan(0);
      $group->getFromDB($group_id);

      $group_user = new \Group_User();
      $this->integer(
         (int)$group_user->add([
            'groups_id' => $group_id,
            'users_id'  => $user->fields['id'],
         ])
      )->isGreaterThan(0);

      $calendars = [
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -407,15 +407,14 @@
     */
    public function testPropfindOnPrincipalCalendar() {
 
-      $login = TU_USER;
-      $pass  = TU_PASS;
+      $login = 'tech';
+      $pass  = 'tech';
       $user  = getItemByTypeName('User', $login);
-
-      $this->login($login, $pass);
 
       $group = new \Group();
       $group_id = (int)$group->add([
-         'name' => 'Test group'
+         'name'    => 'Test group',
+         'is_task' => 1,
       ]);
       $this->integer($group_id)->isGreaterThan(0);
       $group->getFromDB($group_id);
@@ -427,6 +426,8 @@
             'users_id'  => $user->fields['id'],
          ])
       )->isGreaterThan(0);
+
+      $this->login($login, $pass);
 
       $calendars = [
          [
@@ -485,6 +486,62 @@
          $this->integer(
             (int)$xpath->evaluate('count(' . $result_path . '/d:propstat/d:prop/cal:supported-calendar-component-set/cal:comp[@name="VTODO"])')
          )->isEqualTo(1);
+      }
+   }
+
+   /**
+    * Test ACL on main objects.
+    */
+   public function testAcl() {
+
+      $user  = getItemByTypeName('User', 'tech');
+
+      $group = new \Group();
+      $group_id = (int)$group->add([
+         'name'    => 'Test group',
+         'is_task' => 1,
+      ]);
+      $this->integer($group_id)->isGreaterThan(0);
+      $group->getFromDB($group_id);
+
+      $group_user = new \Group_User();
+      $this->integer(
+         (int)$group_user->add([
+            'groups_id' => $group_id,
+            'users_id'  => $user->fields['id'],
+         ])
+      )->isGreaterThan(0);
+
+      $objects = [
+         'principals/users/' . $user->fields['name'],
+         'calendars/users/' . $user->fields['name'] . '/calendar/',
+         'principals/groups/' . $group_id,
+         'calendars/groups/' . $group_id . '/calendar/',
+      ];
+
+      $users_access = [
+         'normal' => 'HTTP/1.1 403 Forbidden',
+         'tech'   => 'HTTP/1.1 200 OK',
+      ];
+
+      foreach ($users_access as $username => $expected_status) {
+         $this->login($username, $username);
+
+         foreach ($objects as $path) {
+            $server = $this->getServerInstance('PROPFIND', $path);
+
+            $this->validateThatAuthenticationIsRequired($server);
+
+            $server->httpRequest->addHeader('Authorization', 'Basic ' . base64_encode($username . ':' . $username));
+
+            $response = new \Sabre\HTTP\Response();
+            $server->invokeMethod($server->httpRequest, $response, false);
+            $this->validateResponseIsOk($response, 207, 'application/xml'); // 207 'Multi-Status'
+
+            $xpath = $this->getXpathFromResponse($response);
+            $result_path = '/d:multistatus/d:response[1]';
+            $this->string($xpath->evaluate('string(' . $result_path . '/d:propstat/d:status)'))->isEqualTo($expected_status);
+         }
       }
    }
 
@@ -1529,6 +1586,7 @@
     *
     * @param \Sabre\HTTP\Response $response
     * @param integer              $status
+    * @param string|null          $content_type
     */
    private function validateResponseIsOk(\Sabre\HTTP\Response $response, int $status, string $content_type) {
       $this->integer($response->getStatus())->isEqualTo($status);
```
