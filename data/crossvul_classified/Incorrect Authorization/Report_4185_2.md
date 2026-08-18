# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4185_2
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4185_2`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 125-165 of the vulnerable file.

     * Internal variable to specify if the record was loaded from cache.
     *
     * @var bool
     */
    protected $loadedFromCache = false;

    /**
     * Create a new query builder instance.
     *
     * @param  \October\Rain\Halcyon\Datasource\DatasourceInterface  $datasource
     * @param  \October\Rain\Halcyon\Processors\Processor  $processor
     * @return void
     */
    public function __construct(DatasourceInterface $datasource, Processor $processor)
    {
        $this->datasource = $datasource;
        $this->processor = $processor;
    }

    /**
     * Switches mode to select a single template by its name.
     *
     * @param  string  $fileName
     * @return $this
     */
    public function whereFileName($fileName)
    {
        $this->selectSingle = $this->model->getFileNameParts($fileName);

        return $this;
    }

    /**
     * Set the directory name which the query is targeting.
     *
     * @param  string  $dirName
     * @return $this
     */
    public function from($dirName)
    {
        $this->from = $dirName;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -142,120 +142,13 @@
     }
 
     /**
-     * Switches mode to select a single template by its name.
-     *
-     * @param  string  $fileName
-     * @return $this
-     */
-    public function whereFileName($fileName)
-    {
-        $this->selectSingle = $this->model->getFileNameParts($fileName);
-
-        return $this;
-    }
-
-    /**
-     * Set the directory name which the query is targeting.
-     *
-     * @param  string  $dirName
-     * @return $this
-     */
-    public function from($dirName)
-    {
-        $this->from = $dirName;
-
-        return $this;
-    }
-
-    /**
-     * Set the "offset" value of the query.
-     *
-     * @param  int  $value
-     * @return $this
-     */
-    public function offset($value)
-    {
-        $this->offset = max(0, $value);
-
-        return $this;
-    }
-
-    /**
-     * Alias to set the "offset" value of the query.
-     *
-     * @param  int  $value
-     * @return \October\Rain\Halcyon\Builder|static
-     */
-    public function skip($value)
-    {
-        return $this->offset($value);
-    }
-
-    /**
-     * Set the "limit" value of the query.
-     *
-     * @param  int  $value
-     * @return $this
-     */
-    public function limit($value)
-    {
-        if ($value >= 0) {
-            $this->limit = $value;
-        }
-
-        return $this;
-    }
-
-    /**
-     * Alias to set the "limit" value of the query.
-     *
-     * @param  int  $value
-     * @return \October\Rain\Halcyon\Builder|static
-     */
-    public function take($value)
-    {
-        return $this->limit($value);
-    }
-
-    /**
-     * Find a single template by its file name.
-     *
-     * @param  string $fileName
-     * @return mixed|static
-     */
-    public function find($fileName)
-    {
-        return $this->whereFileName($fileName)->first();
-    }
-
-    /**
-     * Execute the query and get the first result.
-     *
-     * @return mixed|static
-     */
-    public function first()
-    {
-        return $this->limit(1)->get()->first();
-    }
-
-    /**
-     * Execute the query as a "select" statement.
-     *
-     * @param  array  $columns
-     * @return \October\Rain\Halcyon\Collection|static[]
-     */
-    public function get($columns = ['*'])
-    {
-        if (!is_null($this->cacheMinutes)) {
-            $results = $this->getCached($columns);
-        }
-        else {
-            $results = $this->getFresh($columns);
-        }
-
-        $models = $this->getModels($results ?: []);
-
-        return $this->model->newCollection($models);
+     * Get the compiled file content representation of the query.
+     *
+     * @return string
+     */
+    public function toCompiled()
+    {
+        return $this->processor->processUpdate($this, []);
     }
 
     /**
@@ -279,6 +172,105 @@
         $collection = new Collection($results);
 
         return $collection->lists($column, $key);
+    }
+
+    /**
+     * Set the "limit" value of the query.
+     *
+     * @param  int  $value
+     * @return $this
+     */
+    public function limit($value)
+    {
+        if ($value >= 0) {
+            $this->limit = $value;
+        }
+
+        return $this;
+    }
+
+    /**
+     * Alias to set the "limit" value of the query.
+     *
+     * @param  int  $value
+     * @return \October\Rain\Halcyon\Builder|static
+     */
+    public function take($value)
+    {
+        return $this->limit($value);
+    }
+
+    /**
+     * Set the "offset" value of the query.
+     *
+     * @param  int  $value
+     * @return $this
+     */
+    public function offset($value)
+    {
+        $this->offset = max(0, $value);
+
+        return $this;
+    }
+
+    /**
+     * Alias to set the "offset" value of the query.
+     *
+     * @param  int  $value
+     * @return \October\Rain\Halcyon\Builder|static
+     */
+    public function skip($value)
+    {
+        return $this->offset($value);
+    }
+
+    /**
+     * Set the directory name which the query is targeting.
+     *
+     * @param  string  $dirName
+     * @return $this
+     */
+    public function from($dirName)
+    {
+        $this->from = $dirName;
+
+        return $this;
+    }
+
+    /**
+     * Find a single template by its file name.
+     *
+     * @param  string $fileName
+     * @return mixed|static
+     */
+    public function find($fileName)
+    {
+        return $this->whereFileName($fileName)->first();
+    }
+
+    /**
+     * Execute the query and get the first result.
+     *
+     * @return mixed|static
+     */
+    public function first()
+    {
+        return $this->limit(1)->get()->first();
+    }
+
+    /**
+     * Switches mode to select a single template by its name.
+     *
+     * @param  string  $fileName
+     * @return $this
+     */
+    public function whereFileName($fileName)
+    {
+        $this->validateFileName($fileName);
+
+        $this->selectSingle = $this->model->getFileNameParts($fileName);
+
+        return $this;
     }
 
     /**
@@ -321,30 +313,23 @@
     }
 
     /**
-     * Set a model instance for the model being queried.
-     *
-     * @param  \October\Rain\Halcyon\Model  $model
-     * @return $this
-     */
-    public function setModel(Model $model)
-    {
-        $this->model = $model;
-
-        $this->extensions = $this->model->getAllowedExtensions();
-
-        $this->from($this->model->getObjectTypeDirName());
-
-        return $this;
-    }
-
-    /**
-     * Get the compiled file content representation of the query.
-     *
-     * @return string
-     */
-    public function toCompiled()
-    {
-        return $this->processor->processUpdate($this, []);
+     * Execute the query as a "select" statement.
+     *
+     * @param  array  $columns
+     * @return \October\Rain\Halcyon\Collection|static[]
+     */
+    public function get($columns = ['*'])
+    {
+        if (!is_null($this->cacheMinutes)) {
+            $results = $this->getCached($columns);
+        }
+        else {
+            $results = $this->getFresh($columns);
+        }
+
+        $models = $this->getModels($results ?: []);
+
+        return $this->model->newCollection($models);
     }
 
     /**
@@ -408,10 +393,9 @@
     /**
      * Delete a record from the database.
      *
-     * @param  string  $fileName
      * @return int
      */
-    public function delete($fileName = null)
+    public function delete()
     {
         $this->validateFileName();
 
@@ -440,6 +424,33 @@
             $name,
             $extension
         );
+    }
+
+    /**
+     * Set a model instance for the model being queried.
+     *
+     * @param  \October\Rain\Halcyon\Model  $model
+     * @return $this
+     */
+    public function setModel(Model $model)
+    {
+        $this->model = $model;
+
+        $this->extensions = $this->model->getAllowedExtensions();
+
+        $this->from($this->model->getObjectTypeDirName());
+
+        return $this;
+    }
+
+    /**
+     * Get the model instance being queried.
+     *
+     * @return \October\Rain\Halcyon\Model
+     */
+    public function getModel()
+    {
+        return $this->model;
     }
 
     /**
@@ -468,16 +479,6 @@
         return $models->all();
     }
 
-    /**
-     * Get the model instance being queried.
-     *
-     * @return \October\Rain\Halcyon\Model
-     */
-    public function getModel()
-    {
-        return $this->model;
-    }
-
     //
     // Validation (Hard)
     //
@@ -778,9 +779,8 @@
      *
      * @param  string  $method
      * @param  array   $parameters
-     * @return mixed
-     *
      * @throws \BadMethodCallException
+     * @return void
      */
     public function __call($method, $parameters)
     {
```
