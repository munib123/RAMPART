# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3113_4
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3113_4`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 90-130 of the vulnerable file.

		$allowproxy = false;

		// get faster but less acurate results
		$whois->deep_whois = empty( $_GET['fast'] );

		// To use special whois servers (see README)
		//$whois->UseServer( 'uk', 'whois.nic.uk:1043?{hname} {ip} {query}' );
		//$whois->UseServer( 'au', 'whois-check.ausregistry.net.au' );

		// Comment the following line to disable support for non ICANN tld's
		$whois->non_icann = true;

		$result = $whois->Lookup( $query );

		$winfo = '<pre style="height: '.( $window_height - 200 ).'px; overflow: auto;">';
		if( ! empty( $result['rawdata'] ) )
		{
			// Highlight lines starting with orgname: or org-name: (case insensitive)
			for( $i = 0; $i < count( $result['rawdata'] ); $i++ )
			{
				if( preg_match( '/^(orgname:|org-name:)/i', $result['rawdata'][$i] ) )
				{
					$result['rawdata'][$i] = '<span style="font-weight: bold; background-color: yellow;">'.$result['rawdata'][$i].'</span>';
				}
			}
			$winfo .= format_to_output( implode( $result['rawdata'], "\n" ) );
		}
		else
		{
			$winfo = format_to_output( implode( $whois->Query['errstr'], "\n" ) )."<br></br>";
		}
		$winfo .= '</pre>';

		echo $winfo;
		break;

	case 'add_plugin_sett_set':
		// Dislay a new Plugin(User)Settings set ( it's used only from plugins with "array" type settings):

		// This does not require CSRF because it doesn't update the db, it only displays a new block of empty plugin setting fields

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -107,7 +107,7 @@
 			// Highlight lines starting with orgname: or org-name: (case insensitive)
 			for( $i = 0; $i < count( $result['rawdata'] ); $i++ )
 			{
-				if( preg_match( '/^(orgname:|org-name:)/i', $result['rawdata'][$i] ) )
+				if( preg_match( '/^(orgname:|org-name:|descr:)/i', $result['rawdata'][$i] ) )
 				{
 					$result['rawdata'][$i] = '<span style="font-weight: bold; background-color: yellow;">'.$result['rawdata'][$i].'</span>';
 				}
@@ -161,113 +161,6 @@
 
 		$Form = new Form(); // fake Form to display plugin setting
 		autoform_display_field( $set_path, $r['set_meta'], $Form, $set_type, $Plugin, NULL, $r['set_node'] );
-		break;
-
-	case 'set_object_link_position':
-		// Change a position of a link on the edit item screen (fieldset "Images & Attachments")
-
-		// Check that this action request is not a CSRF hacked request:
-		$Session->assert_received_crumb( 'link' );
-
-		// Check item/comment edit permission below after we have the $LinkOwner object ( we call LinkOwner->check_perm ... )
-
-		param('link_ID', 'integer', true);
-		param('link_position', 'string', true);
-
-		// Don't display the inline position reminder again until the user logs out or loses the session cookie
-		if( $link_position == 'inline' )
-		{
-			$Session->set( 'display_inline_reminder', 'false' );
-		}
-
-		$LinkCache = & get_LinkCache();
-		if( ( $Link = & $LinkCache->get_by_ID( $link_ID ) ) === false )
-		{	// Bad request with incorrect link ID
-			echo '';
-			exit(0);
-		}
-		$LinkOwner = & $Link->get_LinkOwner();
-
-		// Check permission:
-		$LinkOwner->check_perm( 'edit', true );
-
-		if( $Link->set( 'position', $link_position ) && $Link->dbupdate() )
-		{ // update was successful
-			echo 'OK';
-
-			// Update last touched date of Owners
-			$LinkOwner->update_last_touched_date();
-
-			if( $link_position == 'cover' && $LinkOwner->type == 'item' )
-			{ // Position "Cover" can be used only by one link
-			  // Replace previous position with "Inline"
-				$DB->query( 'UPDATE T_links
-						SET link_position = "aftermore"
-					WHERE link_ID != '.$DB->quote( $link_ID ).'
-						AND link_itm_ID = '.$DB->quote( $LinkOwner->Item->ID ).'
-						AND link_position = "cover"' );
-			}
-		}
-		else
-		{ // return the current value on failure
-			echo $Link->get( 'position' );
-		}
-		break;
-
-	case 'update_links_order':
-		// Update the order of all links at one time:
-
-		// Check that this action request is not a CSRF hacked request:
-		$Session->assert_received_crumb( 'link' );
-
-		$link_IDs = param( 'links', 'string' );
-
-		if( empty( $link_IDs ) )
-		{ // No links to update, wrong request, exit here:
-			break;
-		}
-
-		$link_IDs = explode( ',', $link_IDs );
-
-		// Check permission by first link:
-		$LinkCache = & get_LinkCache();
-		if( ( $Link = & $LinkCache->get_by_ID( $link_IDs[0] ) ) === false )
-		{ // Bad request with incorrect link ID
-			exit(0);
-		}
-		$LinkOwner = & $Link->get_LinkOwner();
-		// Check permission:
-		$LinkOwner->check_perm( 'edit', true );
-
-		$DB->begin( 'SERIALIZABLE' );
-
-		// Get max order value of the links:
-		$max_link_order = intval( $DB->get_var( 'SELECT MAX( link_order )
-			 FROM T_links
-			WHERE link_ID IN ( '.$DB->quote( $link_IDs ).' )' ) );
-
-		// Initialize parts of sql queries to update the links order:
-		$fake_sql_update_strings = '';
-		$real_sql_update_strings = '';
-		$real_link_order = 0;
-		foreach( $link_IDs as $link_ID )
-		{
-			$max_link_order++;
-			$fake_sql_update_strings .= ' WHEN link_ID = '.$DB->quote( $link_ID ).' THEN '.$max_link_order;
-			$real_link_order++;
-			$real_sql_update_strings .= ' WHEN link_ID = '.$DB->quote( $link_ID ).' THEN '.$real_link_order;
-		}
-
-		// Do firstly fake ordering start with max order, to avoid duplicate entry error:
-		$DB->query( 'UPDATE T_links
-			  SET link_order = CASE '.$fake_sql_update_strings.' ELSE link_order END
-			WHERE link_ID IN ( '.$DB->quote( $link_IDs ).' )' );
-		// Do real ordering start with number 1:
-		$DB->query( 'UPDATE T_links
-			  SET link_order = CASE '.$real_sql_update_strings.' ELSE link_order END
-			WHERE link_ID IN ( '.$DB->quote( $link_IDs ).' )' );
-
-		$DB->commit();
 		break;
 
 	case 'edit_comment':
@@ -816,9 +709,9 @@
 		// Check permission:
 		$current_User->check_perm( 'files', 'add', true, $fileroot_ID );
 
-		param( 'path', 'string' );
-		param( 'oldfile', 'string' );
-		param( 'newfile', 'string' );
+		param( 'path', 'filepath' );
+		param( 'oldfile', 'filepath' );
+		param( 'newfile', 'filepath' );
 		param( 'format', 'string' );
 
 		$fileroot = explode( '_', $fileroot_ID );
@@ -863,7 +756,7 @@
 		param( 'link_owner_ID', 'integer', true );
 		// Additional params, Used to highlight file/folder
 		param( 'root', 'string', '' );
-		param( 'path', 'string', '' );
+		param( 'path', 'filepath', '' );
 		param( 'fm_highlight', 'string', '' );
 
 		$additional_params = empty( $root ) ? '' : '&amp;root='.$root;
@@ -873,6 +766,36 @@
 		echo '<div style="background:#FFF;height:90%">'
 				.'<span id="link_attachment_loader" class="loader_img absolute_center" title="'.T_('Loading...').'"></span>'
 				.'<iframe src="'.$admin_url.'?ctrl=files&amp;mode=upload&amp;ajax_request=1&amp;iframe_name='.$iframe_name.'&amp;fm_mode=link_object&amp;link_type='.$link_owner_type.'&amp;link_object_ID='.$link_owner_ID.$additional_params.'"'
+					.' width="100%" height="100%" marginwidth="0" marginheight="0" align="top" scrolling="auto" frameborder="0"'
+					.' onload="document.getElementById(\'link_attachment_loader\').style.display=\'none\'">loading</iframe>'
+			.'</div>';
+
+		break;
+
+	case 'file_attachment':
+		// The content for popup window to link the files to the items/comments
+
+		// Check that this action request is not a CSRF hacked request:
+		$Session->assert_received_crumb( 'file' );
+
+		// Check permission:
+		$current_User->check_perm( 'files', 'view' );
+
+		param( 'iframe_name', 'string', '' );
+		param( 'field_name', 'string', '' );
+		// Additional params, Used to highlight file/folder
+		param( 'root', 'string', '' );
+		param( 'path', 'string', '' );
+		param( 'fm_highlight', 'string', '' );
+
+		$additional_params = empty( $root ) ? '' : '&amp;root='.$root;
+		$additional_params .= empty( $path ) ? '' : '&amp;path='.$path;
+		$additional_params .= empty( $fm_highlight ) ? '' : '&amp;fm_highlight='.$fm_highlight;
+		//$additional_params .= empty( $field_name ) ? '' : '&amp;field_name='.$field_name;
+
+		echo '<div style="background:#FFF;height:90%">'
+				.'<span id="link_attachment_loader" class="loader_img absolute_center" title="'.T_('Loading...').'"></span>'
+				.'<iframe src="'.$admin_url.'?ctrl=files&amp;mode=upload&amp;field_name='.$field_name.'&amp;ajax_request=1&amp;iframe_name='.$iframe_name.'&amp;fm_mode=file_select'.$additional_params.'"'
 					.' width="100%" height="100%" marginwidth="0" marginheight="0" align="top" scrolling="auto" frameborder="0"'
 					.' onload="document.getElementById(\'link_attachment_loader\').style.display=\'none\'">loading</iframe>'
 			.'</div>';
```
