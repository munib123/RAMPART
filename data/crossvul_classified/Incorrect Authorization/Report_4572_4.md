# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4572_4
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4572_4`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 239-279 of the vulnerable file.

     *
     * @return JsonResponse
     */
    public function getAvailableEntityFieldsAction(Request $request)
    {
        $fieldsProviderFinder = $this->get('prestashop.core.import.fields_provider_finder');
        try {
            $fieldsProvider = $fieldsProviderFinder->find($request->get('entity'));
            $fieldsCollection = $fieldsProvider->getCollection();
            $entityFields = $fieldsCollection->toArray();
        } catch (NotSupportedImportEntityException $e) {
            $entityFields = [];
        }

        return $this->json($entityFields);
    }

    /**
     * Process the import.
     *
     * @AdminSecurity("is_granted(['read','update', 'create','delete'], request.get('_legacy_controller'))", redirectRoute="admin_import")
     * @DemoRestricted(redirectRoute="admin_import")
     *
     * @param Request $request
     *
     * @return JsonResponse
     */
    public function processImportAction(Request $request)
    {
        $errors = [];
        $requestValidator = $this->get('prestashop.core.import.request_validator');

        try {
            $requestValidator->validate($request);
        } catch (UnavailableImportFileException $e) {
            $errors[] = $this->trans('To proceed, please upload a file first.', 'Admin.Advparameters.Notification');
        }

        if (!empty($errors)) {
            return $this->json([
                'errors' => $errors,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -256,7 +256,7 @@
     /**
      * Process the import.
      *
-     * @AdminSecurity("is_granted(['read','update', 'create','delete'], request.get('_legacy_controller'))", redirectRoute="admin_import")
+     * @AdminSecurity("is_granted(['update', 'create', 'delete'], request.get('_legacy_controller'))", redirectRoute="admin_import")
      * @DemoRestricted(redirectRoute="admin_import")
      *
      * @param Request $request
```
