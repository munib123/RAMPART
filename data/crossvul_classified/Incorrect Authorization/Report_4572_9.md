# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4572_9
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4572_9`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 245-285 of the vulnerable file.

     *
     * @Template("@PrestaShop/Admin/Product/CatalogPage/Lists/list.html.twig")
     *
     * @param Request $request
     * @param int $limit The size of the listing
     * @param int $offset The offset of the listing
     * @param string $orderBy To order product list
     * @param string $sortOrder To order product list
     * @param string $view full|quicknav To change default template used to render the content
     *
     * @return array|Template|Response
     */
    public function listAction(
        Request $request,
        $limit = 10,
        $offset = 0,
        $orderBy = 'id_product',
        $sortOrder = 'asc',
        $view = 'full'
    ) {
        /** @var $productProvider ProductInterfaceProvider */
        $productProvider = $this->get('prestashop.core.admin.data_provider.product_interface');
        $adminProductWrapper = $this->get('prestashop.adapter.admin.wrapper.product');
        $totalCount = 0;

        $this->get('prestashop.service.product')->cleanupOldTempProducts();

        $products = $request->attributes->get('products', null); // get from action subcall data, if any
        $lastSql = $request->attributes->get('last_sql', null); // get from action subcall data, if any

        if ($products === null) {
            // get old values from persistence (before the current update)
            $persistedFilterParameters = $productProvider->getPersistedFilterParameters();
            /** @var ListParametersUpdater $listParametersUpdater */
            $listParametersUpdater = $this->get('prestashop.adapter.product.list_parameters_updater');
            $listParameters = $listParametersUpdater->buildListParameters(
                $request->query->all(),
                $persistedFilterParameters,
                compact('offset', 'limit', 'orderBy', 'sortOrder')
            );
            $offset = $listParameters['offset'];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -262,6 +262,10 @@
         $sortOrder = 'asc',
         $view = 'full'
     ) {
+        if (!$this->isGranted(array(PageVoter::READ), self::PRODUCT_OBJECT)) {
+            return $this->redirect('admin_dashboard');
+        }
+
         /** @var $productProvider ProductInterfaceProvider */
         $productProvider = $this->get('prestashop.core.admin.data_provider.product_interface');
         $adminProductWrapper = $this->get('prestashop.adapter.admin.wrapper.product');
```
