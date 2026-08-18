# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2274_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2274_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 96-141 of the vulnerable file.

	}
	
	return $markup;
}

/**
* AJAX function for grid pagination
* 
* @since 2.0.0
*/
function gce_ajax() {
	
	$nonce = $_POST['gce_nonce'];
 
    // check to see if the submitted nonce matches with the
    // generated nonce we created earlier
    if ( ! wp_verify_nonce( $nonce, 'gce_ajax_nonce' ) ) {
        die ( 'Request has failed.');
	} 
   
	   $ids    = $_POST['gce_feed_ids'];
	   $title  = $_POST['gce_title_text'];
	   $month  = $_POST['gce_month'];
	   $year   = $_POST['gce_year'];
	   $paging = $_POST['gce_paging'];
	   $type   = $_POST['gce_type'];

	   $title = ( 'null' == $title ) ? null : $title;

	   $args = array(
		   'title_text' => $title,
		   'month'      => $month,
		   'year'       => $year,
		   'paging'     => $paging
	   );

	   if ( 'page' == $type ) {
		   echo gce_print_calendar( $ids, 'grid', $args );
	   } elseif ( 'widget' == $type ) {
		   $args['widget'] = 1;
		   echo gce_print_calendar( $ids, 'grid', $args );
	   }
	   
   die();
}
add_action( 'wp_ajax_nopriv_gce_ajax', 'gce_ajax' );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -113,12 +113,12 @@
         die ( 'Request has failed.');
 	} 
    
-	   $ids    = $_POST['gce_feed_ids'];
-	   $title  = $_POST['gce_title_text'];
-	   $month  = $_POST['gce_month'];
-	   $year   = $_POST['gce_year'];
-	   $paging = $_POST['gce_paging'];
-	   $type   = $_POST['gce_type'];
+	   $ids    = esc_html( $_POST['gce_feed_ids'] );
+	   $title  = esc_html( $_POST['gce_title_text'] );
+	   $month  = esc_html( $_POST['gce_month'] );
+	   $year   = esc_html( $_POST['gce_year'] );
+	   $paging = esc_html( $_POST['gce_paging'] );
+	   $type   = esc_html( $_POST['gce_type'] );
 
 	   $title = ( 'null' == $title ) ? null : $title;
 
@@ -157,16 +157,16 @@
         die ( 'Request has failed.');
 	}
   
-	$grouped          = $_POST['gce_grouped'];
-	$start            = $_POST['gce_start'];
-	$ids              = $_POST['gce_feed_ids'];
-	$title_text       = $_POST['gce_title_text'];
-	$sort             = $_POST['gce_sort'];
-	$paging           = $_POST['gce_paging'];
-	$paging_interval  = $_POST['gce_paging_interval'];
-	$paging_direction = $_POST['gce_paging_direction'];
-	$start_offset     = $_POST['gce_start_offset'];
-	$paging_type      = $_POST['gce_paging_type'];
+	$grouped          = esc_html( $_POST['gce_grouped'] );
+	$start            = esc_html( $_POST['gce_start'] );
+	$ids              = esc_html( $_POST['gce_feed_ids'] );
+	$title_text       = esc_html( $_POST['gce_title_text'] );
+	$sort             = esc_html( $_POST['gce_sort'] );
+	$paging           = esc_html( $_POST['gce_paging'] );
+	$paging_interval  = esc_html( $_POST['gce_paging_interval'] );
+	$paging_direction = esc_html( $_POST['gce_paging_direction'] );
+	$start_offset     = esc_html( $_POST['gce_start_offset'] );
+	$paging_type      = esc_html( $_POST['gce_paging_type'] );
 	
 	if( $paging_direction == 'back' ) {
 		if( $paging_type == 'month' ) {
```
