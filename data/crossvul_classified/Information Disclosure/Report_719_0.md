# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 719_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `719_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 5-45 of the vulnerable file.

 *
 * @license http://www.mailcleaner.net/open/licence_en.html MailCleaner Public License
 * @copyright 2015 Fastnet SA
 */

/**
 * Newsletters controller
 */
class NewslettersController extends Zend_Controller_Action
{
    public function indexAction()
    {
        die();
    }
    
    public function allowAction()
    {        
        $status = 0;
        
        $eximId = $this->getRequest()->getParam('id');

        $spam = new Default_Model_DbTable_Spam();

        $row = $spam->fetchRow($spam->select()->where('exim_id = ?', $eximId));
                
        if (!empty($row)) {
            $status = 1;
            
            $recipient = $row->to_user.'@'.$row->to_domain;
            
	    $storage = $row->store_slave;

            $sender = $this->getFromHeader($eximId, $recipient);
            
            $status = 2;
            
            if ($sender) {
                
                $status = 3;
                
                $data = array(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,6 +22,8 @@
         $status = 0;
         
         $eximId = $this->getRequest()->getParam('id');
+	
+	if (strlen($eximId) == 0) { die(); }
 
         $spam = new Default_Model_DbTable_Spam();
 
```
