# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3113_5
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3113_5`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 52-92 of the vulnerable file.

		debug_die( 'No permission to get file (not logged in)!', array('status'=>'403 Forbidden') );
	}


	// fp> I don't think we need the following if public_access_to_media
	if( preg_match( '/^collection_(\d+)$/', $root, $perm_blog ) )
	{	// OK, we got a blog ID:
		$perm_blog = $perm_blog[1];
	}
	else
	{	// No blog ID, we will check the global group perm
		$perm_blog = NULL;
	}
	//pre_dump( $perm_blog );

	// Check permission (#2):
	$current_User->check_perm( 'files', 'view', true, $perm_blog );
}

// Load the other params:
param( 'path', 'string', true );
param( 'size', 'string', NULL ); // Can be used for images.
param( 'size_x', 'integer', 1 ); // Ratio size, can be 1, 2 and etc.
param( 'mtime', 'integer', 0 );  // used for unique URLs (that never expire).

if( $size_x != 1 && $size_x != 2 )
{ // Allow only 1x and 2x sizes, in order to avoid hack that creates many x versions
	$size_x = 1;
}

// TODO: dh> this failed with filenames containing multiple dots!
if ( false !== strpos( urldecode( $path ), '..' ) )
// TODO: dh> fix this better. by adding is_relative_path()?
// fp> the following doesn't look secure. I can't take the risk. What if the path ends with or is just '..' ? I don't want to allow this to go through.
// if( preg_match( '~\.\.[/\\\]~', urldecode( $path ) ) )
{
	debug_die( 'Relative pathnames not allowed!' );
}

// Load fileroot info:
$FileRootCache = & get_FileRootCache();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -69,7 +69,7 @@
 }
 
 // Load the other params:
-param( 'path', 'string', true );
+param( 'path', 'filepath', true );
 param( 'size', 'string', NULL ); // Can be used for images.
 param( 'size_x', 'integer', 1 ); // Ratio size, can be 1, 2 and etc.
 param( 'mtime', 'integer', 0 );  // used for unique URLs (that never expire).
```
