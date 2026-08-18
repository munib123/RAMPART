# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3708_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3708_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 690-731 of the vulnerable file.

					foreach($incident->media as $media)
					{
						if ($media->media_type == 4)
						{
							$incident_news[] = $media->media_link;
						}
						elseif ($media->media_type == 2)
						{
							$incident_video[] = $media->media_link;
						}
						elseif ($media->media_type == 1)
						{
							$incident_photo[] = $media->media_link;
						}
					}

					// Get Geometries via SQL query as ORM can't handle Spatial Data
					$sql = "SELECT AsText(geometry) as geometry, geometry_label,
						geometry_comment, geometry_color, geometry_strokewidth
						FROM ".Kohana::config('database.default.table_prefix')."geometry
						WHERE incident_id=".$id;
					$query = $db->query($sql);
					foreach ( $query as $item )
					{
						$geometry = array(
								"geometry" => $item->geometry,
								"label" => $item->geometry_label,
								"comment" => $item->geometry_comment,
								"color" => $item->geometry_color,
								"strokewidth" => $item->geometry_strokewidth
							);
						$form['geometry'][] = json_encode($geometry);
					}

					// Combine Everything
					$incident_arr = array(
						'location_id' => $incident->location->id,
						'form_id' => $incident->form_id,
						'locale' => $incident->locale,
						'incident_title' => $incident->incident_title,
						'incident_description' => $incident->incident_description,
						'incident_date' => date('m/d/Y', strtotime($incident->incident_date)),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -707,8 +707,8 @@
 					$sql = "SELECT AsText(geometry) as geometry, geometry_label,
 						geometry_comment, geometry_color, geometry_strokewidth
 						FROM ".Kohana::config('database.default.table_prefix')."geometry
-						WHERE incident_id=".$id;
-					$query = $db->query($sql);
+						WHERE incident_id = ?";
+					$query = $db->query($sql, $id);
 					foreach ( $query as $item )
 					{
 						$geometry = array(
```
