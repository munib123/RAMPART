# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4572_6
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4572_6`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 49-89 of the vulnerable file.

     * @return array Template parameters
     */
    public function indexAction(Request $request)
    {
        $legacyController = $request->attributes->get('_legacy_controller');

        $form = $this->get('prestashop.admin.customer_preferences.form_handler')->getForm();

        return [
            'layoutTitle' => $this->trans('Customers', 'Admin.Navigation.Menu'),
            'requireAddonsSearch' => true,
            'enableSidebar' => true,
            'help_link' => $this->generateSidebarLink($legacyController),
            'form' => $form->createView(),
        ];
    }

    /**
     * Process the Customer Preferences configuration form.
     *
     * @AdminSecurity("is_granted(['read','update', 'create','delete'], request.get('_legacy_controller'))", message="You do not have permission to update this.", redirectRoute="admin_customer_preferences")
     * @DemoRestricted(redirectRoute="admin_customer_preferences")
     *
     * @param Request $request
     *
     * @return RedirectResponse
     */
    public function processAction(Request $request)
    {
        $formHandler = $this->get('prestashop.admin.customer_preferences.form_handler');

        $form = $formHandler->getForm();
        $form->handleRequest($request);

        if ($form->isSubmitted()) {
            $data = $form->getData();

            if ($errors = $formHandler->save($data)) {
                $this->flashErrors($errors);

                return $this->redirectToRoute('admin_customer_preferences');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -66,7 +66,7 @@
     /**
      * Process the Customer Preferences configuration form.
      *
-     * @AdminSecurity("is_granted(['read','update', 'create','delete'], request.get('_legacy_controller'))", message="You do not have permission to update this.", redirectRoute="admin_customer_preferences")
+     * @AdminSecurity("is_granted(['update', 'create','delete'], request.get('_legacy_controller'))", message="You do not have permission to update this.", redirectRoute="admin_customer_preferences")
      * @DemoRestricted(redirectRoute="admin_customer_preferences")
      *
      * @param Request $request
```
