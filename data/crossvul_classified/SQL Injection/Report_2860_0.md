# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2860_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2860_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 46-86 of the vulnerable file.

      'F' => 'Full',
      'V' => 'InitCatalog',
      'C' => 'Catalog',
      'O' => 'VolumeToCatalog',
      'd' => 'DiskToCatalog',
      'A' => 'Data'
 );

 try {
    // Check client_id and period received by POST request
    if (!is_null(CHttpRequest::get_Value('client_id'))) {
       
       $clientid = CHttpRequest::get_Value('client_id');

       // Verify if client_id is a valid integer
       if( !filter_var( $clientid, FILTER_VALIDATE_INT)) {
          throw new Exception('Critical: provided parameter (client_id) is not valid');
       }

       $period = CHttpRequest::get_Value('period');

       $view->assign( 'no_report_options', 'false');
       
       // Client informations
       $client_info  = $client->getClientInfos($clientid);
       $view->assign('client_name', $client_info['name']);
       $view->assign('client_os', $client_info['os']);
       $view->assign('client_arch', $client_info['arch']);
       $view->assign('client_version', $client_info['version']);
       
       // Get job names for the client
       $jobs = new Jobs_Model();
       
       foreach ($jobs->get_Jobs_List($clientid) as $jobname) {
          // Last good client's for each backup jobs
          $query  = 'SELECT Job.Name, Job.Jobid, Job.Level, Job.Endtime, Job.Jobbytes, Job.Jobfiles, Status.JobStatusLong FROM Job ';
          $query .= "LEFT JOIN Status ON Job.JobStatus = Status.JobStatus ";
          $query .= "WHERE Job.Name = '$jobname' AND Job.JobStatus = 'T' AND Job.Type = 'B' ";
          $query .= 'ORDER BY Job.EndTime DESC ';
          $query .= 'LIMIT 1';

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -63,6 +63,15 @@
        }
 
        $period = CHttpRequest::get_Value('period');
+
+       // Check if period is an integer and listed in known periods
+       if(!array_key_exists( $period, $periods_list)) {
+          throw new Exception('Critical: provided value for (period) is unknown or not valid');
+       }
+
+       if(!filter_var($period, FILTER_VALIDATE_INT)) {
+          throw new Exception('Critical: provided value for (period) is unknown or not valid');
+       }
 
        $view->assign( 'no_report_options', 'false');
        
```
