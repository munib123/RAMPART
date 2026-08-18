# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 3711_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3711_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 21-61 of the vulnerable file.


    public function __construct($api_service)
    {
        parent::__construct($api_service);
    }
    
    public function perform_task()
    {
        // by request
        if($this->api_service->verify_array_index($this->request, 'by') )
        {
            $this->by = $this->request['by'];

            switch ($this->by)
            {
                case "all":
                    $this->response_data = $this->_get_all_comments();
                break;
            
                case "spam":
                    $this->response_data = $this->_get_spam_comments();
                break;
            
                case "pending":
                    $this->response_data = $this->_get_pending_comments();
                break;
            
                case "approved":
                    $this->response_data = $this->_get_approved_comments();
                break;

			    case "reportid":
				    if ( ! $this->api_service->verify_array_index($this->request, 'id'))
                    {
                        $this->set_error_message(array(
                            "error" => $this->api_service->get_error_msg(001, 'id')
                    ));
                        return;
                    }
                    else
                    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,10 +38,24 @@
                 break;
             
                 case "spam":
+									// Check for admin access on all comments
+									if ( ! $this->api_service->_login(TRUE) )
+									{
+										$this->set_error_message($this->response(2));
+										return;
+									}
+									
                     $this->response_data = $this->_get_spam_comments();
                 break;
             
                 case "pending":
+									// Check for admin access on all comments
+						  		if ( ! $this->api_service->_login(TRUE) )
+									{
+										$this->set_error_message($this->response(2));
+										return;
+									}
+									
                     $this->response_data = $this->_get_pending_comments();
                 break;
             
@@ -89,6 +103,13 @@
         else if($this->api_service->verify_array_index(
             $this->request, 'action'))
         {
+				  		// Check for admin access on all comments
+				  		if ( ! $this->api_service->_login(TRUE) )
+							{
+								$this->set_error_message($this->response(2));
+								return;
+							}
+					
             $this->comment_action();
             return;
         }
```
