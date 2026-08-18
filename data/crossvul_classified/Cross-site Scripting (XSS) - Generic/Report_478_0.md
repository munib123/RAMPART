# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 478_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `478_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 4118-4158 of the vulnerable file.

							<label>
								<input type="radio" name="search_within" id="search_within-1" value="1"<?php if ($within) echo ' checked="checked"'; ?> onclick="search_(1);" />
								<?php echo gettext('Within'); ?>
							</label>
							<label>
								<input type="radio" name="search_within" id="search_within-0" value="1"<?php if (!$within) echo ' checked="checked"'; ?> onclick="search_(0);" />
								<?php echo gettext('New'); ?>
							</label>
							<?php
						}
						if (count($fields) > 1) {
							?>
							<ul>
        <li><label><input type="checkbox" name="checkall_searchfields" id="checkall_searchfields" checked="checked">* <?php echo gettext('Check/uncheck all'); ?> *</label></li>
								<?php
								foreach ($fields as $display => $key) {
									echo '<li><label><input id="SEARCH_' . html_encode($key) . '" name="SEARCH_' . html_encode($key) . '" type="checkbox"';
									if (in_array($key, $query_fields)) {
										echo ' checked="checked" ';
									}
									echo ' value="' . html_encode($key) . '"  /> ' . $display . "</label></li>" . "\n";
								}
								?>
							</ul>
							<?php
						}
						?>
					</div>
					<?php
				}
				?>
			</div>
		</form>
	</div><!-- end of search form -->
	<?php
}

/**
 * Returns the a sanitized version of the search string
 *
 * @return string
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4135,7 +4135,7 @@
 									if (in_array($key, $query_fields)) {
 										echo ' checked="checked" ';
 									}
-									echo ' value="' . html_encode($key) . '"  /> ' . $display . "</label></li>" . "\n";
+									echo ' value="' . html_encode($key) . '"  /> ' . html_encode($display) . "</label></li>" . "\n";
 								}
 								?>
 							</ul>
```
