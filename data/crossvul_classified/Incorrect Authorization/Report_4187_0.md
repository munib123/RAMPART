# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4187_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4187_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 123-163 of the vulnerable file.

     */
    protected function registerBackendReportWidgets()
    {
        WidgetManager::instance()->registerReportWidgets(function ($manager) {
            $manager->registerReportWidget(\Backend\ReportWidgets\Welcome::class, [
                'label'   => 'backend::lang.dashboard.welcome.widget_title_default',
                'context' => 'dashboard'
            ]);
        });
    }

    /*
     * Register permissions
     */
    protected function registerBackendPermissions()
    {
        BackendAuth::registerCallback(function ($manager) {
            $manager->registerPermissions('October.Backend', [
                'backend.access_dashboard' => [
                    'label' => 'system::lang.permissions.view_the_dashboard',
                    'tab'   => 'system::lang.permissions.name'
                ],
                'backend.manage_default_dashboard' => [
                    'label' => 'system::lang.permissions.manage_default_dashboard',
                    'tab'   => 'system::lang.permissions.name',
                ],
                'backend.manage_users' => [
                    'label' => 'system::lang.permissions.manage_other_administrators',
                    'tab'   => 'system::lang.permissions.name'
                ],
                'backend.impersonate_users' => [
                    'label' => 'system::lang.permissions.impersonate_users',
                    'tab'   => 'system::lang.permissions.name',
                ],
                'backend.manage_preferences' => [
                    'label' => 'system::lang.permissions.manage_preferences',
                    'tab'   => 'system::lang.permissions.name'
                ],
                'backend.manage_editor' => [
                    'label' => 'system::lang.permissions.manage_editor',
                    'tab'   => 'system::lang.permissions.name'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -140,31 +140,34 @@
             $manager->registerPermissions('October.Backend', [
                 'backend.access_dashboard' => [
                     'label' => 'system::lang.permissions.view_the_dashboard',
-                    'tab'   => 'system::lang.permissions.name'
+                    'tab'   => 'system::lang.permissions.name',
                 ],
                 'backend.manage_default_dashboard' => [
                     'label' => 'system::lang.permissions.manage_default_dashboard',
                     'tab'   => 'system::lang.permissions.name',
+                    'roles' => UserRole::CODE_DEVELOPER,
                 ],
                 'backend.manage_users' => [
                     'label' => 'system::lang.permissions.manage_other_administrators',
-                    'tab'   => 'system::lang.permissions.name'
+                    'tab'   => 'system::lang.permissions.name',
+                    'roles' => UserRole::CODE_DEVELOPER,
                 ],
                 'backend.impersonate_users' => [
                     'label' => 'system::lang.permissions.impersonate_users',
                     'tab'   => 'system::lang.permissions.name',
+                    'roles' => UserRole::CODE_DEVELOPER,
                 ],
                 'backend.manage_preferences' => [
                     'label' => 'system::lang.permissions.manage_preferences',
-                    'tab'   => 'system::lang.permissions.name'
+                    'tab'   => 'system::lang.permissions.name',
                 ],
                 'backend.manage_editor' => [
                     'label' => 'system::lang.permissions.manage_editor',
-                    'tab'   => 'system::lang.permissions.name'
+                    'tab'   => 'system::lang.permissions.name',
                 ],
                 'backend.manage_branding' => [
                     'label' => 'system::lang.permissions.manage_branding',
-                    'tab'   => 'system::lang.permissions.name'
+                    'tab'   => 'system::lang.permissions.name',
                 ],
                 'media.manage_media' => [
                     'label' => 'backend::lang.permissions.manage_media',
```
