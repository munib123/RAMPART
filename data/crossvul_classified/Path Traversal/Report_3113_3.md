# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3113_3
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3113_3`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 1337-1377 of the vulnerable file.

			$admin_skin = $UserSettings->get( 'admin_skin', $current_User->ID );
			$is_admin_page = true;
			require_once $adminskins_path.$admin_skin.'/_adminUI.class.php';
			$AdminUI = new AdminUI();
		}
		else
		{ // Load Blog skin
			$BlogCache = & get_BlogCache();
			$Collection = $Blog = & $BlogCache->get_by_ID( $blog_ID, true );
			$skin_ID = $Blog->get_skin_ID();
			$SkinCache = & get_SkinCache();
			$Skin = & $SkinCache->get_by_ID( $skin_ID );
		}

		$display_mode = 'js';
		$form_action = get_htsrv_url().'profile_update.php';

		require $inc_path.'users/views/_user_groups.form.php';
		break;

	case 'test_api':
		// Spec action to test API from ctrl=system:
		echo 'ok';
		break;

	default:
		$Ajaxlog->add( T_('Incorrect action!'), 'error' );
		break;
}

$disp = NULL;
$ctrl = NULL;

if( $current_debug || $current_debug_jslog )
{	// debug is ON
	$Ajaxlog->display( NULL, NULL, true, 'all',
					array(
							'error' => array( 'class' => 'jslog_error', 'divClass' => false ),
							'note'  => array( 'class' => 'jslog_note',  'divClass' => false ),
						), 'ul', 'jslog' );
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1354,9 +1354,149 @@
 		require $inc_path.'users/views/_user_groups.form.php';
 		break;
 
+	case 'set_object_link_position':
+		// Change a position of a link on the edit item screen (fieldset "Images & Attachments")
+
+		// Check that this action request is not a CSRF hacked request:
+		$Session->assert_received_crumb( 'link' );
+
+		// Check item/comment edit permission below after we have the $LinkOwner object ( we call LinkOwner->check_perm ... )
+
+		param('link_ID', 'integer', true);
+		param('link_position', 'string', true);
+
+		// Don't display the inline position reminder again until the user logs out or loses the session cookie
+		if( $link_position == 'inline' )
+		{
+			$Session->set( 'display_inline_reminder', 'false' );
+		}
+
+		$LinkCache = & get_LinkCache();
+		if( ( $Link = & $LinkCache->get_by_ID( $link_ID ) ) === false )
+		{	// Bad request with incorrect link ID
+			echo '';
+			exit(0);
+		}
+		$LinkOwner = & $Link->get_LinkOwner();
+
+		// Check permission:
+		$LinkOwner->check_perm( 'edit', true );
+
+		if( $Link->set( 'position', $link_position ) && $Link->dbupdate() )
+		{ // update was successful
+			echo 'OK';
+
+			// Update last touched date of Owners
+			$LinkOwner->update_last_touched_date();
+
+			if( $link_position == 'cover' && $LinkOwner->type == 'item' )
+			{ // Position "Cover" can be used only by one link
+			  // Replace previous position with "Inline"
+				$DB->query( 'UPDATE T_links
+						SET link_position = "aftermore"
+					WHERE link_ID != '.$DB->quote( $link_ID ).'
+						AND link_itm_ID = '.$DB->quote( $LinkOwner->Item->ID ).'
+						AND link_position = "cover"' );
+			}
+		}
+		else
+		{ // return the current value on failure
+			echo $Link->get( 'position' );
+		}
+		break;
+
+	case 'update_links_order':
+		// Update the order of all links at one time:
+
+		// Check that this action request is not a CSRF hacked request:
+		$Session->assert_received_crumb( 'link' );
+
+		$link_IDs = param( 'links', 'string' );
+
+		if( empty( $link_IDs ) )
+		{ // No links to update, wrong request, exit here:
+			break;
+		}
+
+		$link_IDs = explode( ',', $link_IDs );
+
+		// Check permission by first link:
+		$LinkCache = & get_LinkCache();
+		if( ( $Link = & $LinkCache->get_by_ID( $link_IDs[0] ) ) === false )
+		{ // Bad request with incorrect link ID
+			exit(0);
+		}
+		$LinkOwner = & $Link->get_LinkOwner();
+		// Check permission:
+		$LinkOwner->check_perm( 'edit', true );
+
+		$DB->begin( 'SERIALIZABLE' );
+
+		// Get max order value of the links:
+		$max_link_order = intval( $DB->get_var( 'SELECT MAX( link_order )
+			 FROM T_links
+			WHERE link_ID IN ( '.$DB->quote( $link_IDs ).' )' ) );
+
+		// Initialize parts of sql queries to update the links order:
+		$fake_sql_update_strings = '';
+		$real_sql_update_strings = '';
+		$real_link_order = 0;
+		foreach( $link_IDs as $link_ID )
+		{
+			$max_link_order++;
+			$fake_sql_update_strings .= ' WHEN link_ID = '.$DB->quote( $link_ID ).' THEN '.$max_link_order;
+			$real_link_order++;
+			$real_sql_update_strings .= ' WHEN link_ID = '.$DB->quote( $link_ID ).' THEN '.$real_link_order;
+		}
+
+		// Do firstly fake ordering start with max order, to avoid duplicate entry error:
+		$DB->query( 'UPDATE T_links
+			  SET link_order = CASE '.$fake_sql_update_strings.' ELSE link_order END
+			WHERE link_ID IN ( '.$DB->quote( $link_IDs ).' )' );
+		// Do real ordering start with number 1:
+		$DB->query( 'UPDATE T_links
+			  SET link_order = CASE '.$real_sql_update_strings.' ELSE link_order END
+			WHERE link_ID IN ( '.$DB->quote( $link_IDs ).' )' );
+
+		$DB->commit();
+		break;
+
 	case 'test_api':
 		// Spec action to test API from ctrl=system:
 		echo 'ok';
+		break;
+
+	case 'get_file_select_item':
+		$field_params = param( 'params', 'array', true );
+		$field_name = param( 'field_name', 'string', true );
+		$root = param( 'root', 'string', true );
+		$file_path = param( 'path', 'string', true );
+
+		$FileCache = & get_FileCache();
+		list( $root_type, $root_in_type_ID ) = explode( '_', $root, 2 );
+		if( ! ( $current_File = $FileCache->get_by_root_and_path( $root_type, $root_in_type_ID, $file_path ) ) )
+		{	// No file:
+			debug_die( 'No such file' );
+			// Exit here.
+		}
+
+		if( ! $current_File->is_image() )
+		{
+			debug_die( 'Incorrect file type for '.$field_name );
+		}
+
+		// decode params with HTML tags
+		$field_params['field_item_start'] = base64_decode( $field_params['field_item_start'] );
+		$field_params['field_item_end'] = base64_decode( $field_params['field_item_end'] );
+
+		$current_File->load_meta( true ); // erhsatingin > can we force create file meta in DB here or should this whole thing require login?
+		$r = file_select_item( $current_File->ID, $field_params );
+
+		echo json_encode( array(
+				'fieldName' => $field_name,
+				'fieldValue' => $current_File->ID,
+				'item' => base64_encode( $r )
+			) );
 		break;
 
 	default:
```
