# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3745_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3745_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 124-164 of the vulnerable file.

		for ($i = 0; $i < count($path_array) && $i < self::STACK_REPRESENTATIVES; $i++) {
		$tile = new TileSingle($path_array[$i]);
			array_push($this->tiles_array, $tile);
		}
	}
	
	public function forceSize($width_must_fit=false) {
		for ($i = 0; $i < count($this->tiles_array); $i++)
			$this->tiles_array[$i]->forceSize(true);
	}

	public function getWidth() {
		$max = 0;
		for ($i = 0; $i < count($this->tiles_array); $i++) {
			$max = max($max, $this->tiles_array[$i]->getWidth());
		}
		return min(IMAGE_WIDTH, $max);
	}

	public function get() {
		$r = '<div class="title gallery_div">'.$this->stack_name.'</div>';
		for ($i = 0; $i < count($this->tiles_array); $i++) {
			$top = rand(-5, 5);
			$left = rand(-5, 5);
			$img_w = $this->tiles_array[$i]->getWidth();
			$extra = '';
			if ($img_w < IMAGE_WIDTH) {
				$extra = 'width:'.$img_w.'px;';
			}
			$r .= '<div class="miniature_border gallery_div" style="background-image:url(\''.$this->tiles_array[$i]->getMiniatureSrc().'\');margin-top:'.$top.'px; margin-left:'.$left.'px;'.$extra.'"></div>';
		}
		return $r;
	}

	public function getOnHoverAction() {
		return 'javascript:explode(this);return false;';
	}
	
	public function getOnOutAction() {
		return 'javascript:deplode(this);return false;';
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -141,7 +141,7 @@
 	}
 
 	public function get() {
-		$r = '<div class="title gallery_div">'.$this->stack_name.'</div>';
+		$r = '<div class="title gallery_div">'.htmlentities($this->stack_name).'</div>';
 		for ($i = 0; $i < count($this->tiles_array); $i++) {
 			$top = rand(-5, 5);
 			$left = rand(-5, 5);
@@ -168,7 +168,7 @@
 	}
 	
 	public function getOnClickAction() {
-		return 'javascript:openNewGal(\''.$this->stack_name.'\');';
+		return 'javascript:openNewGal(\''.htmlentities($this->stack_name).'\');';
 	}
 
 	private $tiles_array;
```
