# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 5290_0
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5290_0`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 41-82 of the vulnerable file.

    function editor() {
        global $user;
        
        $file = new expFile($this->params['id']);
        
        $canSaveOg = $user->id==$file->poster || $user->is_admin ? 1 : 0 ;
	    if (file_exists(BASE.$file->directory.$file->filename)) {
			$file->copyToDirectory(BASE.$this->cacheDir);
			assign_to_template(array(
                'image'=>$file,
                'update'=>$this->params['update'],
                'saveog'=>$canSaveOg
            ));
	    } else {
		    flash('error',gt('The file').' "'.BASE.$file->directory.$file->filename.'" '.gt('does not exist on the server.'));
		    redirect_to(array("controller"=>'file',"action"=>'picker',"ajax_action"=>1,"update"=>$this->params['update'],"filter"=>$this->params['filter']));
	    }
    }
    
    public function exitEditor() {

        //eDebug($this->params,true);
        switch ($this->params['exitType']) {
            case 'saveAsCopy':
                $oldimage = new expFile($this->params['fid']);                
                $copyname = expFile::resolveDuplicateFilename($oldimage->path); 
                copy(BASE.$this->cacheDir."/".$this->params['cpi'],$oldimage->directory.$copyname); //copy the edited file over to the files dir
                $newFile = new expFile(array("filename"=>$copyname)); //construct a new expFile
                $newFile->directory = $oldimage->directory;
                $newFile->title = $oldimage->title;
                $newFile->shared = $oldimage->shared;
                $newFile->mimetype = $oldimage->mimetype;
                $newFile->posted = time();
                $newFile->filesize = filesize(BASE.$this->cacheDir."/".$this->params['cpi']);
                $resized = getimagesize(BASE.$this->cacheDir."/".$this->params['cpi']);
                $newFile->image_width = $resized[0];
                $newFile->image_height = $resized[1];
                $newFile->alt = $oldimage->alt;
                $newFile->is_image = $oldimage->is_image;
                $newFile->save(); //Save it to the database

                break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,8 +58,11 @@
     }
     
     public function exitEditor() {
-
-        //eDebug($this->params,true);
+        // clean up parameters
+        $this->params['fid'] = intval($this->params['fid']);
+        if (!empty($this->params['cpi']) && strpos($this->params['cpi'], '..') !== false) {
+            $this->params['exitType'] = 'error';
+        }
         switch ($this->params['exitType']) {
             case 'saveAsCopy':
                 $oldimage = new expFile($this->params['fid']);                
```
