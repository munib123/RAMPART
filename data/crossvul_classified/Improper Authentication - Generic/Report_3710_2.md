# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 3710_2
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3710_2`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 11-51 of the vulnerable file.

 * @author     Ushahidi Team <team@ushahidi.com>
 * @package    Ushahidi - http://source.ushahididev.com
 * @module     API Controller
 * @copyright  Ushahidi - http://www.ushahidi.com
 * @license    http://www.gnu.org/copyleft/lesser.html GNU Lesser General Public License (LGPL)
 */
class Report_Api_Object extends Api_Object_Core {

    private $error_string = ''; // To hold the string of error messages
    
    public function __construct($api_service)
    {
        parent::__construct($api_service);
    }

    /**
     * Services the request for reporting an incident via the API
     */
    public function perform_task()
    {
        $ret_value = $this->_submit();
        
        $this->response_data =  $this->response($ret_value, $this->error_string);
    }
    
    /**
     * The actual reporting -
     *
     * @return int
     */
    private function _submit() 
    {
        // Setup and initialize form field names
        $form = array(
            'incident_title' => '',
            'incident_description' => '',
            'incident_date' => '',
            'incident_hour' => '',
            'incident_minute' => '',
            'incident_ampm' => '',
            'latitude' => '',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,6 +28,13 @@
      */
     public function perform_task()
     {
+  		// If user doesn't have member perms and allow_reports is disabled, Throw auth error
+  		if ( ! Kohana::config('settings.allow_reports') AND ! $this->api_service->_login(FALSE, TRUE) )
+			{
+				$this->set_error_message($this->response(2));
+				return;
+			}
+			
         $ret_value = $this->_submit();
         
         $this->response_data =  $this->response($ret_value, $this->error_string);
```
