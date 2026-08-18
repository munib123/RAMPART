# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 4133_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4133_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 80-120 of the vulnerable file.

      'DISTINCT'  => true,
      'FROM'      => $table,
      'LEFT JOIN' => [
         'glpi_networkports'  => [
            'ON'  => [
               'glpi_networkports'  => 'items_id',
               $table               => 'id', [
                  'AND' => [
                     'glpi_networkports.items_id'           => $_POST['item'],
                     'glpi_networkports.itemtype'           => $_POST["itemtype"],
                     'glpi_networkports.instantiation_type' => $_POST['instantiation_type']
                  ]
               ]
            ]
         ],
         'glpi_networkports_networkports' => [
            'ON'  => [
               'glpi_networkports_networkports' => 'networkports_id_1',
               'glpi_networkports'              => 'id', [
                  'OR'  => [
                     'glpi_networkports_networkports.networkports_id_2' => $DB->quoteName('glpi_networkports.id')
                  ]
               ]
            ]
         ]
      ] + $joins,
      'WHERE'     => [
         'glpi_networkports_networkports.id' => null,
         'NOT'                               => ['glpi_networkports.id' => null],
         'glpi_networkports.id'              => ['<>', $_POST['networkports_id']],
         "$table.is_deleted"                 => 0,
         "$table.is_template"                => 0
      ],
      'ORDERBY'   => 'glpi_networkports.id'
   ];
   $iterator = $DB->request($criteria);

   echo "<br>";

   $values = [];
   while ($data = $iterator->next()) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -97,7 +97,7 @@
                'glpi_networkports_networkports' => 'networkports_id_1',
                'glpi_networkports'              => 'id', [
                   'OR'  => [
-                     'glpi_networkports_networkports.networkports_id_2' => $DB->quoteName('glpi_networkports.id')
+                     'glpi_networkports_networkports.networkports_id_2' => new QueryExpression($DB->quoteName('glpi_networkports.id'))
                   ]
                ]
             ]
```
