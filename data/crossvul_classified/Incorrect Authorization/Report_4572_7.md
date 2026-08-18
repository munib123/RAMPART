# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4572_7
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4572_7`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 51-91 of the vulnerable file.

    public function indexAction(Request $request)
    {
        $legacyController = $request->attributes->get('_legacy_controller');

        $geolocationForm = $this->getGeolocationFormHandler()->getForm();
        $geoLiteCityChecker = $this->get('prestashop.core.geolocation.geo_lite_city.checker');

        return $this->render('@PrestaShop/Admin/Improve/International/Geolocation/index.html.twig', [
            'layoutTitle' => $this->trans('Geolocation', 'Admin.Navigation.Menu'),
            'enableSidebar' => true,
            'help_link' => $this->generateSidebarLink($legacyController),
            'geolocationForm' => $geolocationForm->createView(),
            'geolocationDatabaseAvailable' => $geoLiteCityChecker->isAvailable(),
        ]);
    }

    /**
     * Process geolocation configuration form.
     *
     * @AdminSecurity(
     *     "is_granted(['read', 'update', 'create', 'delete'], request.get('_legacy_controller'))",
     *     message="You do not have permission to edit this.",
     *     redirectRoute="admin_geolocation"
     * )
     * @DemoRestricted(redirectRoute="admin_geolocation_index")
     *
     * @param Request $request
     *
     * @return RedirectResponse
     */
    public function saveOptionsAction(Request $request)
    {
        $geolocationFormHandler = $this->getGeolocationFormHandler();

        $geolocationForm = $geolocationFormHandler->getForm();
        $geolocationForm->handleRequest($request);

        if ($geolocationForm->isSubmitted()) {
            $errors = $geolocationFormHandler->save($geolocationForm->getData());

            if (empty($errors)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -68,7 +68,7 @@
      * Process geolocation configuration form.
      *
      * @AdminSecurity(
-     *     "is_granted(['read', 'update', 'create', 'delete'], request.get('_legacy_controller'))",
+     *     "is_granted(['update', 'create', 'delete'], request.get('_legacy_controller'))",
      *     message="You do not have permission to edit this.",
      *     redirectRoute="admin_geolocation"
      * )
```
