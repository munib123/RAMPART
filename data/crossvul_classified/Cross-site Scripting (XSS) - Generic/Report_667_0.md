# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 667_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `667_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 185-225 of the vulnerable file.


	public function column_type( $item ) {
		$return = __( $item->object_type, 'aryo-activity-log' );
		
		$return = apply_filters( 'aal_table_list_column_type', $return, $item );
		return $return;
	}

	public function column_label( $item ) {
		$return = '';
		if ( ! empty( $item->object_subtype ) ) {
			$pt     = get_post_type_object( $item->object_subtype );
			$return = ! empty( $pt->label ) ? $pt->label : $item->object_subtype;
		}

		$return = apply_filters( 'aal_table_list_column_label', $return, $item );
		return $return;
	}
	
	public function column_description( $item ) {
		$return = $item->object_name;
		
		switch ( $item->object_type ) {
			case 'Post' :
				$return = sprintf( '<a href="%s">%s</a>', get_edit_post_link( $item->object_id ), $item->object_name );
				break;
			
			case 'Taxonomy' :
				if ( ! empty( $item->object_id ) )
					$return = sprintf( '<a href="%s">%s</a>', get_edit_term_link( $item->object_id, $item->object_subtype ), $item->object_name );
				break;
			
			case 'Comments' :
				if ( ! empty( $item->object_id ) && $comment = get_comment( $item->object_id ) ) {
					$return = sprintf( '<a href="%s">%s #%d</a>', get_edit_comment_link( $item->object_id ), $item->object_name, $item->object_id );
				}
				break;
			
			case 'Export' :
				if ( 'all' === $item->object_name ) {
					$return = __( 'All', 'aryo-activity-log' );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -202,16 +202,16 @@
 	}
 	
 	public function column_description( $item ) {
-		$return = $item->object_name;
+		$return = esc_html( $item->object_name );
 		
 		switch ( $item->object_type ) {
 			case 'Post' :
-				$return = sprintf( '<a href="%s">%s</a>', get_edit_post_link( $item->object_id ), $item->object_name );
+				$return = sprintf( '<a href="%s">%s</a>', get_edit_post_link( $item->object_id ), esc_html( $item->object_name ) );
 				break;
 			
 			case 'Taxonomy' :
 				if ( ! empty( $item->object_id ) )
-					$return = sprintf( '<a href="%s">%s</a>', get_edit_term_link( $item->object_id, $item->object_subtype ), $item->object_name );
+					$return = sprintf( '<a href="%s">%s</a>', get_edit_term_link( $item->object_id, $item->object_subtype ), esc_html( $item->object_name ) );
 				break;
 			
 			case 'Comments' :
@@ -224,7 +224,7 @@
 				if ( 'all' === $item->object_name ) {
 					$return = __( 'All', 'aryo-activity-log' );
 				} else {
-					$pt     = get_post_type_object( $item->object_name );
+					$pt = get_post_type_object( $item->object_name );
 					$return = ! empty( $pt->label ) ? $pt->label : $item->object_name;
 				}
 				break;
```
