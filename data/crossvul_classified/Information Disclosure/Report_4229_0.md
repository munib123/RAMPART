# CrossVul Fix Pair: Exposure of Resource to Wrong Sphere in php
**Pair ID:** 4229_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-668
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4229_0`)

## Vulnerability Information & PoC

## Description
Exposure of Resource to Wrong Sphere - Resources such as files and directories may be inadvertently exposed through mechanisms such as insecure permissions, or when a program accidentally operates on the wrong object.

## Vulnerable Code
```php
Lines 26-66 of the vulnerable file.

        Route::get('settings', 'PollerController@settingsTab')->name('poller.settings');
        Route::get('performance', 'PollerController@performanceTab')->name('poller.performance');
        Route::resource('{id}/settings', 'PollerSettingsController', ['as' => 'poller'])->only(['update', 'destroy']);
    });
    Route::get('locations', 'LocationController@index');
    Route::resource('preferences', 'UserPreferencesController', ['only' => ['index', 'store']]);
    Route::resource('users', 'UserController');
    Route::get('about', 'AboutController@index');
    Route::get('authlog', 'UserController@authlog');
    Route::get('overview', 'OverviewController@index')->name('overview');
    Route::get('/', 'OverviewController@index')->name('home');
    Route::match(['get', 'post'], 'device/{device}/{tab?}/{vars?}', 'DeviceController@index')
        ->name('device')->where(['vars' => '.*']);

    // Maps
    Route::group(['prefix' => 'maps', 'namespace' => 'Maps'], function () {
        Route::get('devicedependency', 'DeviceDependencyController@dependencyMap');
    });

    // admin pages
    Route::group(['guard' => 'admin'], function () {
        Route::get('settings/{tab?}/{section?}', 'SettingsController@index')->name('settings');
        Route::put('settings/{name}', 'SettingsController@update')->name('settings.update');
        Route::delete('settings/{name}', 'SettingsController@destroy')->name('settings.destroy');
    });

    // old route redirects
    Route::permanentRedirect('poll-log', 'poller/log');

    // Two Factor Auth
    Route::group(['prefix' => '2fa', 'namespace' => 'Auth'], function () {
        Route::get('', 'TwoFactorController@showTwoFactorForm')->name('2fa.form');
        Route::post('', 'TwoFactorController@verifyTwoFactor')->name('2fa.verify');
        Route::post('add', 'TwoFactorController@create')->name('2fa.add');
        Route::post('cancel', 'TwoFactorController@cancelAdd')->name('2fa.cancel');
        Route::post('remove', 'TwoFactorController@destroy')->name('2fa.remove');

        Route::post('{user}/unlock', 'TwoFactorManagementController@unlock')->name('2fa.unlock');
        Route::delete('{user}', 'TwoFactorManagementController@destroy')->name('2fa.delete');
    });

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,7 +43,7 @@
     });
 
     // admin pages
-    Route::group(['guard' => 'admin'], function () {
+    Route::group(['middleware' => ['can:admin']], function () {
         Route::get('settings/{tab?}/{section?}', 'SettingsController@index')->name('settings');
         Route::put('settings/{name}', 'SettingsController@update')->name('settings.update');
         Route::delete('settings/{name}', 'SettingsController@destroy')->name('settings.destroy');
```
