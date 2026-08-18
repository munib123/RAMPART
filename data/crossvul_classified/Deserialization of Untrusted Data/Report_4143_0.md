# CrossVul Fix Pair: Deserialization of Untrusted Data in php
**Pair ID:** 4143_0
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4143_0`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```php
Lines 111-151 of the vulnerable file.

			if(file_exists($templateDir . "ban.php")){
				include_once($templateDir . "ban.php");
			}else{
				include_once(SOY2::RootDir() . "template/_sample/ban.php");
			}
			$html = ob_get_contents();
			ob_end_clean();

			return $html;
		}

	    $columnDAO = SOY2DAOFactory::create("SOYInquiry_ColumnDAO");
	    $columns = $columnDAO->getOrderedColumnsByFormId($form->getId());

	    //隠しvalueから入力値を復元する
	    if(isset($_POST["form_value"]) && isset($_POST["form_hash"])){
	    	$value = base64_decode($_POST["form_value"]);

	    	//不正な書き換えでない場合のみ
	    	if(md5($value) == $_POST["form_hash"]){
	    		$_POST["data"] = unserialize($value);
	    	}
	    }

	    //CAPTCHA画像出力
	    if(isset($_GET["captcha"])){

	    	header("Content-Type: image/jpeg");
			$captcha = str_replace(array(".", "/", "\\"), "", $_GET["captcha"]);
			echo file_get_contents(SOY2HTMLConfig::CacheDir() . $captcha . ".jpg");
			//CAPTCHA画像の削除
	    	@unlink(SOY2HTMLConfig::CacheDir() . $captcha . ".jpg");
	    	exit;

	    //CSS出力
	    }else if(isset($_GET["stylesheet"])){

			if(file_exists($templateDir . "style.php")){
		    	header("Content-Type: text/css; charset: UTF-8");
		    	include_once($templateDir . "style.php");
			}else{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -128,7 +128,7 @@
 
 	    	//不正な書き換えでない場合のみ
 	    	if(md5($value) == $_POST["form_hash"]){
-	    		$_POST["data"] = unserialize($value);
+	    		$_POST["data"] = json_decode($value, true);
 	    	}
 	    }
 
@@ -275,8 +275,8 @@
 					$captcha_url = $this->pageUrl . "?captcha=" . $captcha_filename;
 				}
 
-				$hidden_hash = md5(serialize($_POST["data"]));
-				$hidden_value = base64_encode(serialize($_POST["data"]));
+				$hidden_hash = md5(json_encode($_POST["data"]));
+				$hidden_value = base64_encode(json_encode($_POST["data"]));
 
 				$hidden_forms = '<input type="hidden" name="form_hash" value="' . $hidden_hash . '" />';
 				$hidden_forms.= '<input type="hidden" name="form_value" value="' . $hidden_value . '" />';
```
