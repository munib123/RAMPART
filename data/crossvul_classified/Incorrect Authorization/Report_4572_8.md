# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4572_8
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4572_8`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 58-98 of the vulnerable file.

            $this->addFlash('warning', $this->trans('Importing a new language may fail without the OpenSSL module. Please enable "openssl.so" on your server configuration.', 'Admin.International.Notification'));
        }

        $localizationPackImportForm = $this->createForm(ImportLocalizationPackType::class);
        $localizationForm = $this->getLocalizationFormHandler()->getForm();

        return $this->render('@PrestaShop/Admin/Improve/International/Localization/index.html.twig', [
            'layoutHeaderToolbarBtn' => [],
            'layoutTitle' => $this->trans('Localization', 'Admin.Navigation.Menu'),
            'requireAddonsSearch' => true,
            'enableSidebar' => true,
            'help_link' => $this->generateSidebarLink($legacyController),
            'localizationForm' => $localizationForm->createView(),
            'localizationPackImportForm' => $localizationPackImportForm->createView(),
        ]);
    }

    /**
     * Save localization settings.
     *
     * @AdminSecurity("is_granted(['read','update', 'create','delete'], request.get('_legacy_controller'))", message="You do not have permission to edit this.")
     * @DemoRestricted(redirectRoute="admin_localization_index")
     *
     * @param Request $request
     *
     * @return RedirectResponse
     */
    public function saveOptionsAction(Request $request)
    {
        $localizationFormHandler = $this->getLocalizationFormHandler();

        $localizationForm = $localizationFormHandler->getForm();
        $localizationForm->handleRequest($request);

        if ($localizationForm->isSubmitted()) {
            $data = $localizationForm->getData();

            $errors = $localizationFormHandler->save($data);
            if (empty($errors)) {
                $this->addFlash('success', $this->trans('Update successful', 'Admin.Notifications.Success'));

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,7 +75,7 @@
     /**
      * Save localization settings.
      *
-     * @AdminSecurity("is_granted(['read','update', 'create','delete'], request.get('_legacy_controller'))", message="You do not have permission to edit this.")
+     * @AdminSecurity("is_granted(['update', 'create', 'delete'], request.get('_legacy_controller'))", message="You do not have permission to edit this.")
      * @DemoRestricted(redirectRoute="admin_localization_index")
      *
      * @param Request $request
```
