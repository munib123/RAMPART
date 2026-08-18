# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 3710_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3710_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 32-72 of the vulnerable file.

			
	/**
	 * Validation of form fields
	 *
	 * @param array $post Values to be validated
	 */
	public static function validate(array & $post)
	{

		// Exception handling
		if ( ! isset($post) OR ! is_array($post))
			return FALSE;
		
		// Create validation object
		$post = Validation::factory($post)
				->pre_filter('trim', TRUE)
				->add_rules('incident_title','required', 'length[3,200]')
				->add_rules('incident_description','required')
				->add_rules('incident_date','required','date_mmddyyyy')
				->add_rules('incident_hour','required','between[1,12]')
				->add_rules('incident_minute','required','between[0,59]');
			
		if ($post->incident_ampm != "am" AND $post->incident_ampm != "pm")
		{
			$post->add_error('incident_ampm','values');
		}
			
		// Validate for maximum and minimum latitude values
		$post->add_rules('latitude','required','between[-90,90]');
		
		// Validate for maximum and minimum longitude values		
		$post->add_rules('longitude','required','between[-180,180]');	
		$post->add_rules('location_name','required', 'length[3,200]');

		//XXX: Hack to validate for no checkboxes checked
		if ( ! isset($post->incident_category))
		{
			$post->incident_category = "";
			$post->add_error('incident_category','required');
		}
		else
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,9 +49,10 @@
 				->add_rules('incident_description','required')
 				->add_rules('incident_date','required','date_mmddyyyy')
 				->add_rules('incident_hour','required','between[1,12]')
-				->add_rules('incident_minute','required','between[0,59]');
-			
-		if ($post->incident_ampm != "am" AND $post->incident_ampm != "pm")
+				->add_rules('incident_minute','required','between[0,59]')
+				->add_rules('incident_ampm','required');
+			
+		if (isset($post->incident_ampm) AND $post->incident_ampm != "am" AND $post->incident_ampm != "pm")
 		{
 			$post->add_error('incident_ampm','values');
 		}
@@ -117,15 +118,27 @@
 		{
 			$post->add_rules('person_first', 'length[2,100]');
 		}
+		else
+		{
+			$post->person_first = '';
+		}
 
 		if ( ! empty($post->person_last))
 		{
 			$post->add_rules('person_last', 'length[2,100]');
 		}
+		else
+		{
+			$post->person_last = '';
+		}
 
 		if ( ! empty($post->person_email))
 		{
 			$post->add_rules('person_email', 'email', 'length[3,100]');
+		}
+		else
+		{
+			$post->person_email = '';
 		}
 		
 		$post->add_rules('location_id','numeric');
```
