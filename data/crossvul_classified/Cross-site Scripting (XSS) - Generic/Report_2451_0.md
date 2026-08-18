# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2451_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2451_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 24-64 of the vulnerable file.

     */
    public function tableName()
    {
        return '{{surveys_groups}}';
    }

    /**
     * @return array validation rules for model attributes.
     */
    public function rules()
    {
        // NOTE: you should only define rules for those attributes that
        // will receive user inputs.
        return array(
            array('name, sortorder, created_by, title', 'required'),
            array('sortorder, owner_id, parent_id, created_by', 'numerical', 'integerOnly'=>true),
            array('name', 'length', 'max'=>45),
            array('name', 'match', 'pattern'=> '/^[A-Za-z0-9_\.]+$/u','message'=> gT('Group name can contain only alphanumeric character, underscore or dot.')),
            array('title', 'length', 'max'=>100),
            array('description, created, modified', 'safe'),
            array('title, name, description', 'LSYii_Validators'),
            // The following rule is used by search().
            // @todo Please remove those attributes that should not be searched.
            array('gsid, name, title, description, owner_id, parent_id, created, modified, created_by', 'safe', 'on'=>'search'),
        );
    }

    /**
     * @return array relational rules.
     */
    public function relations()
    {
        // NOTE: you may need to adjust the relation name and the related
        // class name for the relations automatically generated below.
        return array(
            'parentgroup' => array(self::BELONGS_TO, 'SurveysGroups', array('parent_id' => 'gsid'), 'together' => true),
            'owner'       => array(self::BELONGS_TO, 'User', 'owner_id', 'together' => true),
        );
    }

    /**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,7 +41,6 @@
             array('name', 'match', 'pattern'=> '/^[A-Za-z0-9_\.]+$/u','message'=> gT('Group name can contain only alphanumeric character, underscore or dot.')),
             array('title', 'length', 'max'=>100),
             array('description, created, modified', 'safe'),
-            array('title, name, description', 'LSYii_Validators'),
             // The following rule is used by search().
             // @todo Please remove those attributes that should not be searched.
             array('gsid, name, title, description, owner_id, parent_id, created, modified, created_by', 'safe', 'on'=>'search'),
```
