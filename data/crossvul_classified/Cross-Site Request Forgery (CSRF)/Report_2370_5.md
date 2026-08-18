# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 2370_5
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2370_5`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1039-1079 of the vulnerable file.

                global $db_list, $global_db_list;
                if ( ! is_array( $db_list ) )
                        return true;

                if ( $this->blogs != '' && preg_match("/(" . $this->blogs . "|" . $this->users . "|" . $this->usermeta . "|" . $this->site . "|" . $this->sitemeta . "|" . $this->sitecategories . ")/i",$query) ) {
                        $action = 'global';
                        $details = $global_db_list[ mt_rand( 0, count( $global_db_list ) -1 ) ];
                        $this->db_global = $details;
                } elseif ( preg_match("/^\\s*(alter table|create|insert|delete|update|replace) /i",$query) ) {
                        $action = 'write';
                        $details = $db_list[ 'write' ][ mt_rand( 0, count( $db_list[ 'write' ] ) -1 ) ];
                        $this->db_write = $details;
                } else {
                        $action = '';
                        $details = $db_list[ 'read' ][ mt_rand( 0, count( $db_list[ 'read' ] ) -1 ) ];
                        $this->db_read = $details;
                }

                $dbhname = "dbh" . $action;
                $this->$dbhname = @mssql_connect( $details[ 'db_host' ], $details[ 'db_user' ], $details[ 'db_password' ] );

                if (!$this->$dbhname ) {
                        $this->bail( sprintf( /*WP_I18N_DB_CONN_ERROR*/"
<h1>Error establishing a database connection</h1>
<p>This either means that the username and password information in your <code>wp-config.php</code> file is incorrect or we can't contact the database server at <code>%s</code>. This could mean your host's database server is down.</p>
<ul>
        <li>Are you sure you have the correct username and password?</li>
        <li>Are you sure that you have typed the correct hostname?</li>
        <li>Are you sure that the database server is running?</li>
</ul>
<p>If you're unsure what these terms mean you should probably contact your host. If you still need help you can always visit the <a href='http://wordpress.org/support/'>WordPress Support Forums</a>.</p>
"/*/WP_I18N_DB_CONN_ERROR*/, $details['db_host'] ), 'db_connect_fail' );
                }

                mssql_min_error_severity(0);
                mssql_min_message_severity(17);
                @mssql_query('SET TEXTSIZE 2147483647');

                $this->select( $details[ 'db_name' ], $this->$dbhname );
        }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1056,6 +1056,7 @@
 
                 $dbhname = "dbh" . $action;
                 $this->$dbhname = @mssql_connect( $details[ 'db_host' ], $details[ 'db_user' ], $details[ 'db_password' ] );
+                $this->is_mysql = false;
 
                 if (!$this->$dbhname ) {
                         $this->bail( sprintf( /*WP_I18N_DB_CONN_ERROR*/"
```
