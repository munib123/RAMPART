# CrossVul Fix Pair: Improper Privilege Management in php
**Pair ID:** 4429_1
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4429_1`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```php
Lines 1-29 of the vulnerable file.

<?php

/**
 * @group xmlrpc
 */
class Tests_XMLRPC_wp_newComment extends WP_XMLRPC_UnitTestCase {

	/**
	 * Post object for shared fixture.
	 *
	 * @var WP_Post
	 */
	public static $post;

	public static function wpSetUpBeforeClass( $factory ) {
		self::make_user_by_role( 'administrator' );
		self::$post = $factory->post->create_and_get();
	}

	function test_valid_comment() {
		$result = $this->myxmlrpcserver->wp_newComment(
			array(
				1,
				'administrator',
				'administrator',
				self::$post->ID,
				array(
					'content' => rand_str( 100 ),
				),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,15 +6,45 @@
 class Tests_XMLRPC_wp_newComment extends WP_XMLRPC_UnitTestCase {
 
 	/**
-	 * Post object for shared fixture.
-	 *
-	 * @var WP_Post
-	 */
-	public static $post;
+	 * Array of posts.
+	 *
+	 * @var WP_Post[]
+	 */
+	public static $posts;
+
+	/**
+	 * User IDs.
+	 *
+	 * Array of user IDs keyed by role.
+	 *
+	 * @var int[]
+	 */
+	public static $user_ids;
 
 	public static function wpSetUpBeforeClass( $factory ) {
-		self::make_user_by_role( 'administrator' );
-		self::$post = $factory->post->create_and_get();
+		self::$user_ids                     = array(
+			'administrator' => self::make_user_by_role( 'administrator' ),
+			'contributor'   => self::make_user_by_role( 'contributor' ),
+		);
+		self::$posts['publish']             = $factory->post->create_and_get();
+		self::$posts['password']            = $factory->post->create_and_get(
+			array(
+				'post_password' => 'xmlrpc',
+				'post_author'   => self::$user_ids['administrator'],
+			)
+		);
+		self::$posts['private']             = $factory->post->create_and_get(
+			array(
+				'post_status' => 'private',
+				'post_author' => self::$user_ids['administrator'],
+			)
+		);
+		self::$posts['private_contributor'] = $factory->post->create_and_get(
+			array(
+				'post_status' => 'private',
+				'post_author' => self::$user_ids['contributor'],
+			)
+		);
 	}
 
 	function test_valid_comment() {
@@ -23,7 +53,7 @@
 				1,
 				'administrator',
 				'administrator',
-				self::$post->ID,
+				self::$posts['publish']->ID,
 				array(
 					'content' => rand_str( 100 ),
 				),
@@ -39,7 +69,7 @@
 				1,
 				'administrator',
 				'administrator',
-				self::$post->ID,
+				self::$posts['publish']->ID,
 				array(
 					'content' => '',
 				),
@@ -59,7 +89,7 @@
 				1,
 				'administrator',
 				'administrator',
-				self::$post->ID,
+				self::$posts['publish']->ID,
 				array(
 					'content' => '   ',
 				),
@@ -79,7 +109,7 @@
 				1,
 				'administrator',
 				'administrator',
-				self::$post->ID,
+				self::$posts['publish']->ID,
 				array(
 					'content' => '0',
 				),
@@ -99,7 +129,7 @@
 				1,
 				'administrator',
 				'administrator',
-				self::$post->ID,
+				self::$posts['publish']->ID,
 				array(
 					'content' => '   ',
 				),
@@ -139,7 +169,7 @@
 			1,
 			'administrator',
 			'administrator',
-			self::$post->ID,
+			self::$posts['publish']->ID,
 			array(
 				'content' => rand_str( 100 ),
 			),
@@ -168,7 +198,7 @@
 			1,
 			'',
 			'',
-			self::$post->ID,
+			self::$posts['publish']->ID,
 			array(
 				'author'       => 'WordPress',
 				'author_email' => 'noreply@wordpress.org',
@@ -193,7 +223,7 @@
 			1,
 			'',
 			'',
-			self::$post->ID,
+			self::$posts['publish']->ID,
 			array(
 				'author'       => 'WordPress',
 				'author_email' => 'noreply at wordpress.org',
@@ -218,7 +248,7 @@
 			1,
 			'administrator',
 			'administrator',
-			self::$post->ID,
+			self::$posts['publish']->ID,
 			array(
 				'author'       => 'WordPress',
 				'author_email' => 'noreply at wordpress.org',
@@ -232,4 +262,131 @@
 
 		$this->assertSame( $user_id, (int) $comment->user_id );
 	}
+
+	/**
+	 * Ensure users can only comment on posts they're permitted to access.
+	 *
+	 * @dataProvider data_comments_observe_post_permissions
+	 *
+	 * @param string $post_key      Post identifier from the self::$posts array.
+	 * @param string $username      Username leaving comment.
+	 * @param bool   $expected      Expected result. True: successfull comment. False: Refused comment.
+	 * @param string $anon_callback Optional. Allow anonymous comment callback. Default __return_false.
+	 */
+	function test_comments_observe_post_permissions( $post_key, $username, $expected, $anon_callback = '__return_false' ) {
+		add_filter( 'xmlrpc_allow_anonymous_comments', $anon_callback );
+
+		$comment_args = array(
+			1,
+			$username,
+			$username,
+			self::$posts[ $post_key ]->ID,
+			array(
+				'author'       => 'WordPress',
+				'author_email' => 'noreply@wordpress.org',
+				'content'      => 'Test Comment',
+			),
+		);
+
+		$result = $this->myxmlrpcserver->wp_newComment( $comment_args );
+		if ( $expected ) {
+			$this->assertInternalType( 'int', $result );
+			return;
+		}
+
+		$this->assertIXRError( $result );
+		$this->assertSame( 403, $result->code );
+	}
+
+	/**
+	 * Data provider for test_comments_observe_post_permissions.
+	 *
+	 * @return array[] {
+	 *     @type string Post identifier from the self::$posts array.
+	 *     @type string Username leaving comment.
+	 *     @type bool   Expected result. True: successfull comment. False: Refused comment.
+	 *     @type string Optional. Allow anonymous comment callback. Default __return_false.
+	 * }
+	 */
+	function data_comments_observe_post_permissions() {
+		return array(
+			// 0: Post author, password protected public post.
+			array(
+				'password',
+				'administrator',
+				true,
+			),
+			// 1: Low privileged non-author, password protected public post.
+			array(
+				'password',
+				'contributor',
+				false,
+			),
+			// 2: Anonymous user, password protected public post.
+			array(
+				'password',
+				'', // Anonymous user.
+				false,
+			),
+			// 3: Anonymous user, anon comments allowed, password protected public post.
+			array(
+				'password',
+				'', // Anonymous user.
+				false,
+				'__return_true',
+			),
+
+			// 4: Post author, private post.
+			array(
+				'private',
+				'administrator',
+				true,
+			),
+			// 5: Low privileged non-author, private post.
+			array(
+				'private',
+				'contributor',
+				false,
+			),
+			// 6: Anonymous user, private post.
+			array(
+				'private',
+				'', // Anonymous user.
+				false,
+			),
+			// 7: Anonymous user, anon comments allowed, private post.
+			array(
+				'private',
+				'', // Anonymous user.
+				false,
+				'__return_true',
+			),
+
+			// 8: High privileged non-author, private post.
+			array(
+				'private_contributor',
+				'administrator',
+				true,
+			),
+			// 9: Low privileged author, private post.
+			array(
+				'private_contributor',
+				'contributor',
+				true,
+			),
+			// 10: Anonymous user, private post.
+			array(
+				'private_contributor',
+				'', // Anonymous user.
+				false,
+			),
+			// 11: Anonymous user, anon comments allowed, private post.
+			array(
+				'private_contributor',
+				'', // Anonymous user.
+				false,
+				'__return_true',
+			),
+		);
+	}
 }
```
