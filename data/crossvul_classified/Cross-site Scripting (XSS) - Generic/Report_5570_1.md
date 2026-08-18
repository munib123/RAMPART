# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5570_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5570_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 264-304 of the vulnerable file.

        $form = new Admin_Form_EditPassword();
        $form->setMethod('POST');

        $request = $this->getRequest();
        if ($request->isPost() && $form->isValid($request->getPost())) {
            $this->_helper->service('user')->save($form->getValues(), $user);
            $this->_helper->flashMessenger(getGS('Password updated'));
            $this->_helper->redirector('edit-password', 'user', 'admin');
        }

        $this->view->form = $form;
    }

    /**
     * Get user for given id
     *
     * @return Newscoop\Entity\User
     */
    protected function getUser()
    {
        $id = $this->_getParam('user', false);
        if (!$id) {
            $this->_helper->flashMessenger(array('error', getGS('User id not specified')));
            $this->_helper->redirector('index');
        }

        $user = $this->userService->find($id);
        if (empty($user)) {
            $this->_helper->flashMessenger(array('error', getGS("User with id '$1' not found", $id)));
            $this->_helper->redirector('index');
        }

        return $user;
    }
    
    public function toggleBanAction()
    {
        $parameters = $this->getRequest()->getParams();
        
        $userRepository = $this->_helper->entity->getRepository('Newscoop\Entity\User');
        $publicationRepository = $this->_helper->entity->getRepository('Newscoop\Entity\Publication');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -281,7 +281,7 @@
      */
     protected function getUser()
     {
-        $id = $this->_getParam('user', false);
+        $id = (int) $this->_getParam('user', false);
         if (!$id) {
             $this->_helper->flashMessenger(array('error', getGS('User id not specified')));
             $this->_helper->redirector('index');
```
