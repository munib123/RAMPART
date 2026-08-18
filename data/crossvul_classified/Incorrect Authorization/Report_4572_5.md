# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4572_5
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4572_5`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 63-103 of the vulnerable file.


        $form = null === $form ? $this->get('prestashop.adapter.performance.form_handler')->getForm() : $form;

        return [
            'layoutHeaderToolbarBtn' => $toolbarButtons,
            'layoutTitle' => $this->trans('Performance', 'Admin.Navigation.Menu'),
            'requireAddonsSearch' => true,
            'requireBulkActions' => false,
            'showContentHeader' => true,
            'enableSidebar' => true,
            'help_link' => $this->generateSidebarLink('AdminPerformance'),
            'requireFilterStatus' => false,
            'form' => $form->createView(),
            'servers' => $this->get('prestashop.adapter.memcache_server.manager')->getServers(),
        ];
    }

    /**
     * Process the Performance configuration form.
     *
     * @AdminSecurity("is_granted(['read','update', 'create','delete'], request.get('_legacy_controller'))", message="You do not have permission to update this.")
     * @DemoRestricted(redirectRoute="admin_performance")
     *
     * @param Request $request
     *
     * @return RedirectResponse
     */
    public function processFormAction(Request $request)
    {
        $this->dispatchHook('actionAdminPerformanceControllerPostProcessBefore', array('controller' => $this));
        $form = $this->get('prestashop.adapter.performance.form_handler')->getForm();
        $form->handleRequest($request);

        if ($form->isSubmitted()) {
            $data = $form->getData();

            $saveErrors = $this->get('prestashop.adapter.performance.form_handler')->save($data);

            if (0 === count($saveErrors)) {
                $this->addFlash('success', $this->trans('Successful update.', 'Admin.Notifications.Success'));

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -80,7 +80,7 @@
     /**
      * Process the Performance configuration form.
      *
-     * @AdminSecurity("is_granted(['read','update', 'create','delete'], request.get('_legacy_controller'))", message="You do not have permission to update this.")
+     * @AdminSecurity("is_granted(['update', 'create', 'delete'], request.get('_legacy_controller'))", message="You do not have permission to update this.")
      * @DemoRestricted(redirectRoute="admin_performance")
      *
      * @param Request $request
```
