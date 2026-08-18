# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in php
**Pair ID:** 450_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `450_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```php
Lines 24-64 of the vulnerable file.

	 */
	private $asset_manager;

	/**
	 * Class constructor, which basically only hooks the init function on the init hook
	 */
	public function __construct() {
		add_action( 'init', array( $this, 'init' ), 20 );
		$this->asset_manager = new WPSEO_Admin_Asset_Manager();
	}

	/**
	 * Make sure the needed scripts are loaded for admin pages
	 */
	public function init() {
		if ( filter_input( INPUT_GET, 'wpseo_reset_defaults' ) && wp_verify_nonce( filter_input( INPUT_GET, 'nonce' ), 'wpseo_reset_defaults' ) && current_user_can( 'manage_options' ) ) {
			WPSEO_Options::reset();
			wp_redirect( admin_url( 'admin.php?page=' . WPSEO_Configuration_Page::PAGE_IDENTIFIER ) );
		}

		add_action( 'admin_init', array( $this, 'admin_init' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'config_page_scripts' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'config_page_styles' ) );
	}

	/**
	 * Run admin-specific actions.
	 */
	public function admin_init() {

		$page         = filter_input( INPUT_GET, 'page' );
		$tool         = filter_input( INPUT_GET, 'tool' );
		$export_nonce = filter_input( INPUT_POST, WPSEO_Export::NONCE_NAME );

		if ( 'wpseo_tools' === $page && 'import-export' === $tool && $export_nonce !== null ) {
			$this->do_yoast_export();
		}
	}

	/**
	 * Loads the required styles for the config page.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,24 +41,10 @@
 			wp_redirect( admin_url( 'admin.php?page=' . WPSEO_Configuration_Page::PAGE_IDENTIFIER ) );
 		}
 
-		add_action( 'admin_init', array( $this, 'admin_init' ) );
 		add_action( 'admin_enqueue_scripts', array( $this, 'config_page_scripts' ) );
 		add_action( 'admin_enqueue_scripts', array( $this, 'config_page_styles' ) );
 	}
 
-	/**
-	 * Run admin-specific actions.
-	 */
-	public function admin_init() {
-
-		$page         = filter_input( INPUT_GET, 'page' );
-		$tool         = filter_input( INPUT_GET, 'tool' );
-		$export_nonce = filter_input( INPUT_POST, WPSEO_Export::NONCE_NAME );
-
-		if ( 'wpseo_tools' === $page && 'import-export' === $tool && $export_nonce !== null ) {
-			$this->do_yoast_export();
-		}
-	}
 
 	/**
 	 * Loads the required styles for the config page.
@@ -158,24 +144,4 @@
 			$this->asset_manager->enqueue_script( 'bulk-editor' );
 		}
 	}
-
-	/**
-	 * Runs the yoast exporter class to possibly init the file download.
-	 */
-	private function do_yoast_export() {
-		check_admin_referer( WPSEO_Export::NONCE_ACTION, WPSEO_Export::NONCE_NAME );
-
-		if ( ! WPSEO_Capability_Utils::current_user_can( 'wpseo_manage_options' ) ) {
-			return;
-		}
-
-		$wpseo_post       = filter_input( INPUT_POST, 'wpseo' );
-		$include_taxonomy = ! empty( $wpseo_post['include_taxonomy'] );
-		$export           = new WPSEO_Export( $include_taxonomy );
-
-		if ( $export->has_error() ) {
-			add_action( 'admin_notices', array( $export, 'set_error_hook' ) );
-
-		}
-	}
 } /* End of class */
```
