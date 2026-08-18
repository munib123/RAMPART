# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 2569_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2569_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 74-114 of the vulnerable file.

    }

    public function testPasswordIsNotValid()
    {
        $constraint = new UserPassword(array(
            'message' => 'myMessage',
        ));

        $this->encoder->expects($this->once())
            ->method('isPasswordValid')
            ->with(static::PASSWORD, 'secret', static::SALT)
            ->will($this->returnValue(false));

        $this->validator->validate('secret', $constraint);

        $this->buildViolation('myMessage')
            ->assertRaised();
    }

    /**
     * @expectedException \Symfony\Component\Validator\Exception\ConstraintDefinitionException
     */
    public function testUserIsNotValid()
    {
        $user = $this->getMockBuilder('Foo\Bar\User')->getMock();

        $this->tokenStorage = $this->createTokenStorage($user);
        $this->validator = $this->createValidator();
        $this->validator->initialize($this->context);

        $this->validator->validate('secret', new UserPassword());
    }

    protected function createUser()
    {
        $mock = $this->getMockBuilder('Symfony\Component\Security\Core\User\UserInterface')->getMock();

        $mock
            ->expects($this->any())
            ->method('getPassword')
            ->will($this->returnValue(static::PASSWORD))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -91,6 +91,29 @@
     }
 
     /**
+     * @dataProvider emptyPasswordData
+     */
+    public function testEmptyPasswordsAreNotValid($password)
+    {
+        $constraint = new UserPassword(array(
+            'message' => 'myMessage',
+        ));
+
+        $this->validator->validate($password, $constraint);
+
+        $this->buildViolation('myMessage')
+            ->assertRaised();
+    }
+
+    public function emptyPasswordData()
+    {
+        return array(
+            array(null),
+            array(''),
+        );
+    }
+
+    /**
      * @expectedException \Symfony\Component\Validator\Exception\ConstraintDefinitionException
      */
     public function testUserIsNotValid()
```
