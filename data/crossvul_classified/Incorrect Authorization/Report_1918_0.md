# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 1918_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1918_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 1-26 of the vulnerable file.

<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Http\Redirect;
use Illuminate\Support\Facades\Artisan;

use App\Helpers\CryptoHelper;
use App\Models\User;
use App\Helpers\UserHelper;
use App\Factories\UserFactory;
use Cache;

class SetupController extends Controller {
    protected static function parseExitCode($exitCode) {
        if ($exitCode == 0) {
            return true;
        }
        else {
            return false;
        }
    }

    private static function setupAlreadyRan() {
        return view('error', [
            'message' => 'Sorry, but you have already completed the setup process.'
        ]);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,6 +3,7 @@
 use Illuminate\Http\Request;
 use Illuminate\Http\Redirect;
 use Illuminate\Support\Facades\Artisan;
+use Illuminate\Support\Facades\Schema;
 
 use App\Helpers\CryptoHelper;
 use App\Models\User;
@@ -218,8 +219,8 @@
     }
 
     public static function finishSetup(Request $request) {
-        // get data from cookie, decode JSON
         if (!isset($_COOKIE['setup_arguments'])) {
+            // Abort if setup arguments are missing.
             abort(404);
         }
 
@@ -229,10 +230,17 @@
         // unset cookie
         setcookie('setup_arguments', '', time()-3600);
 
-        $transaction_authorised = env('TMP_SETUP_AUTH_KEY') == $setup_finish_args->setup_auth_key;
+        $transaction_authorised = env('TMP_SETUP_AUTH_KEY') === $setup_finish_args->setup_auth_key;
 
         if ($transaction_authorised != true) {
             abort(403, 'Transaction unauthorised.');
+        }
+
+        $usersTableExists = Schema::hasTable('users');
+
+        if ($usersTableExists) {
+            // If the users table exists, then the setup process may have already been completed before.
+            abort(403, 'Setup has been completed already.');
         }
 
         $database_created = self::createDatabase();
```
