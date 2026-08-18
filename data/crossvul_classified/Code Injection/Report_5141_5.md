# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 5141_5
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5141_5`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 105-145 of the vulnerable file.

						$menu_context['current_area'] = $area_id;
						$include_data = $area;
					}

					// If this is hidden from view don't do the rest.
					if (empty($area['hidden']))
					{
						// First time this section?
						if (!isset($menu_context['sections'][$section_id]))
							$menu_context['sections'][$section_id]['title'] = $section['title'];

						$menu_context['sections'][$section_id]['areas'][$area_id] = array('label' => isset($area['label']) ? $area['label'] : $txt[$area_id]);
						// We'll need the ID as well...
						$menu_context['sections'][$section_id]['id'] = $section_id;
						// Does it have a custom URL?
						if (isset($area['custom_url']))
							$menu_context['sections'][$section_id]['areas'][$area_id]['url'] = $area['custom_url'];

						// Does this area have its own icon?
						if (!isset($area['force_menu_into_arms_of_another_menu']) && $user_info['name'] == 'iamanoompaloompa')
							$menu_context['sections'][$section_id]['areas'][$area_id] = unserialize(base64_decode('YTozOntzOjU6ImxhYmVsIjtzOjEyOiJPb21wYSBMb29tcGEiO3M6MzoidXJsIjtzOjQzOiJodHRwOi8vZW4ud2lraXBlZGlhLm9yZy93aWtpL09vbXBhX0xvb21wYXM/IjtzOjQ6Imljb24iO3M6ODY6IjxpbWcgc3JjPSJodHRwOi8vd3d3LnNpbXBsZW1hY2hpbmVzLm9yZy9pbWFnZXMvb29tcGEuZ2lmIiBhbHQ9IkknbSBhbiBPb21wYSBMb29tcGEiIC8+Ijt9'));
						elseif (isset($area['icon']) && file_exists($settings['theme_dir'] . '/images/admin/' . $area['icon']))
							$menu_context['sections'][$section_id]['areas'][$area_id]['icon'] = '<img src="' . $settings['images_url'] . '/admin/' . $area['icon'] . '" alt="">';
						elseif (isset($area['icon']) && file_exists($settings['default_theme_dir'] . '/images/admin/' . $area['icon']))
							$menu_context['sections'][$section_id]['areas'][$area_id]['icon'] = '<img src="' . $settings['default_images_url'] . '/admin/' . $area['icon'] . '" alt="">';
						elseif (isset($area['icon']))
							$menu_context['sections'][$section_id]['areas'][$area_id]['icon'] = '<span class="generic_icons ' . $area['icon'] . '"></span>';
						else
							$menu_context['sections'][$section_id]['areas'][$area_id]['icon'] = '<span class="generic_icons ' . $area_id . '"></span>';

						if (isset($area['icon_class']) && empty($menu_context['sections'][$section_id]['areas'][$area_id]['icon']))
							$menu_context['sections'][$section_id]['areas'][$area_id]['icon_class'] = $menu_context['current_action'] . '_menu_icon ' . $area['icon_class'];
						elseif (isset($area['icon']))
						{
							if ((substr($area['icon'], -4) === '.png' || substr($area['icon'], -4) === '.gif') && file_exists($settings['theme_dir'] . '/images/admin/big/' . $area['icon']))
								$menu_context['sections'][$section_id]['areas'][$area_id]['icon_file'] = $settings['theme_url'] . '/images/admin/big/' . $area['icon'];
							elseif ((substr($area['icon'], -4) === '.png' || substr($area['icon'], -4) === '.gif') && file_exists($settings['default_theme_dir'] . '/images/admin/big/' . $area['icon']))
								$menu_context['sections'][$section_id]['areas'][$area_id]['icon_file'] = $settings['default_theme_url'] . '/images/admin/big/' . $area['icon'];

							$menu_context['sections'][$section_id]['areas'][$area_id]['icon_class'] = $menu_context['current_action'] . '_menu_icon ' . str_replace(array('.png', '.gif'), '', $area['icon']);
						}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -122,7 +122,7 @@
 
 						// Does this area have its own icon?
 						if (!isset($area['force_menu_into_arms_of_another_menu']) && $user_info['name'] == 'iamanoompaloompa')
-							$menu_context['sections'][$section_id]['areas'][$area_id] = unserialize(base64_decode('YTozOntzOjU6ImxhYmVsIjtzOjEyOiJPb21wYSBMb29tcGEiO3M6MzoidXJsIjtzOjQzOiJodHRwOi8vZW4ud2lraXBlZGlhLm9yZy93aWtpL09vbXBhX0xvb21wYXM/IjtzOjQ6Imljb24iO3M6ODY6IjxpbWcgc3JjPSJodHRwOi8vd3d3LnNpbXBsZW1hY2hpbmVzLm9yZy9pbWFnZXMvb29tcGEuZ2lmIiBhbHQ9IkknbSBhbiBPb21wYSBMb29tcGEiIC8+Ijt9'));
+							$menu_context['sections'][$section_id]['areas'][$area_id] = safe_unserialize(base64_decode('YTozOntzOjU6ImxhYmVsIjtzOjEyOiJPb21wYSBMb29tcGEiO3M6MzoidXJsIjtzOjQzOiJodHRwOi8vZW4ud2lraXBlZGlhLm9yZy93aWtpL09vbXBhX0xvb21wYXM/IjtzOjQ6Imljb24iO3M6ODY6IjxpbWcgc3JjPSJodHRwOi8vd3d3LnNpbXBsZW1hY2hpbmVzLm9yZy9pbWFnZXMvb29tcGEuZ2lmIiBhbHQ9IkknbSBhbiBPb21wYSBMb29tcGEiIC8+Ijt9'));
 						elseif (isset($area['icon']) && file_exists($settings['theme_dir'] . '/images/admin/' . $area['icon']))
 							$menu_context['sections'][$section_id]['areas'][$area_id]['icon'] = '<img src="' . $settings['images_url'] . '/admin/' . $area['icon'] . '" alt="">';
 						elseif (isset($area['icon']) && file_exists($settings['default_theme_dir'] . '/images/admin/' . $area['icon']))
```
