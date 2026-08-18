# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2088_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2088_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 31-71 of the vulnerable file.

        if ( ! $this->request->is_initial() )
        {
            if ($message = rawurldecode($this->request->param('message')))
            {
                $this->_message = $message;
            }
 
            if ($requested_page = rawurldecode($this->request->param('origuri')))
            {
                $this->_requested_page = $requested_page;
            }
        }
        else
        {
            // This one was directly requested, don't allow
            $this->request->action(404);
 
            // Set the requested page accordingly
            $this->_requested_page = Arr::get($_SERVER, 'REQUEST_URI');
        }
 
        $this->response->status((int) $this->request->action());
    }
 
    /**
     * Serves HTTP 404 error page
     */
    public function action_404()
    {
        $this->template->meta_description = 'The requested page '.$this->_requested_page.' not found';
        $this->template->meta_keywords = 'not found, 404';
        $this->template->title = 'Page '.$this->_requested_page.' not found';
 
        $this->template->content = View::factory('pages/error/404')
            ->set('error_message', $this->_message)
            ->set('requested_page', $this->_requested_page);
    }
 
    /**
     * Serves HTTP 500 error page
     */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,7 +48,10 @@
             // Set the requested page accordingly
             $this->_requested_page = Arr::get($_SERVER, 'REQUEST_URI');
         }
- 
+    
+        //sanitize the url....
+        $this->_requested_page = Kohana::sanitize($this->_requested_page);
+        
         $this->response->status((int) $this->request->action());
     }
  
```
