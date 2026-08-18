# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 2276_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2276_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 91-131 of the vulnerable file.

	protected $projection = 10;
	protected $category_id = 1;
	protected $date_submitted = '';
	protected $last_updated = '';
	protected $eta = 10;
	protected $os = '';
	protected $os_build = '';
	protected $platform = '';
	protected $version = '';
	protected $fixed_in_version = '';
	protected $target_version = '';
	protected $build = '';
	protected $view_state = VS_PUBLIC;
	protected $summary = '';
	protected $sponsorship_total = 0;
	protected $sticky = 0;
	protected $due_date = 0;

	# omitted:
	# var $bug_text_id
	protected $profile_id;

	# extended info
	protected $description = '';
	protected $steps_to_reproduce = '';
	protected $additional_information = '';

	# internal helper objects
	private $_stats = null;

	public $attachment_count = null;
	public $bugnotes_count = null;

	private $loading = false;

	/**
	 * return number of file attachment's linked to current bug
	 * @return int
	 */
	public function get_attachment_count() {
		if ( $this->attachment_count === null ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -108,7 +108,7 @@
 
 	# omitted:
 	# var $bug_text_id
-	protected $profile_id;
+	protected $profile_id = 0;
 
 	# extended info
 	protected $description = '';
@@ -310,7 +310,14 @@
 
 		# check due_date format
 		if( is_blank( $this->due_date ) ) {
-			$this_due_date = date_get_null();
+			$this->due_date = date_get_null();
+		}
+		# check date submitted and last modified
+		if( is_blank( $this->date_submitted ) ) {
+			$this->date_submitted = db_now();
+		}
+		if( is_blank( $this->last_updated ) ) {
+			$this->last_updated = db_now();
 		}
 
 		$t_bug_table = db_get_table( 'bug' );
@@ -374,7 +381,8 @@
 					      " . db_param() . ',' . db_param() . ',' . db_param() . ',' . db_param() . ",
 					      " . db_param() . ',' . db_param() . ',' . db_param() . ',' . db_param() . ')';
 
-		db_query_bound( $query, Array( $this->project_id, $this->reporter_id, $this->handler_id, $this->duplicate_id, $this->priority, $this->severity, $this->reproducibility, $t_status, $this->resolution, $this->projection, $this->category_id, db_now(), db_now(), $this->eta, $t_text_id, $this->os, $this->os_build, $this->platform, $this->version, $this->build, $this->profile_id, $this->summary, $this->view_state, $this->sponsorship_total, $this->sticky, $this->fixed_in_version, $this->target_version, $this->due_date ) );
+		db_query_bound( $query, Array( $this->project_id, $this->reporter_id, $this->handler_id, $this->duplicate_id, $this->priority, $this->severity, $this->reproducibility, $t_status, $this->resolution, $this->projection, $this->category_id, $this->date_submitted, $this->last_updated, $this->eta, $t_text_id, $this->os, $this->os_build, $this->platform, $this->version, $this->build, $this->profile_id, $this->summary, $this->view_state, $this->sponsorship_total, $this->sticky, $this->fixed_in_version, $this->target_version, $this->due_date ) );
+
 
 		$this->id = db_insert_id( $t_bug_table );
 
```
