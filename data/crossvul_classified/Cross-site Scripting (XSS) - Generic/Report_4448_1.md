# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4448_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4448_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 31-72 of the vulnerable file.

            'menuLeft'      => [],
            'topMenuRight'  => [],
            'topMenuLeft'   => [],
            'urlDeleteItem' => sc_route('admin_cms_content.delete'),
            'removeList'    => 1, // 1 - Enable function delete list item
            'buttonRefresh' => 1, // 1 - Enable button refresh
            'buttonSort'    => 1, // 1 - Enable button sort
            'css'           => '', 
            'js'            => '',
        ];

        $listTh = [
            'id'          => trans($this->plugin->pathPlugin.'::Content.id'),
            'image'       => trans($this->plugin->pathPlugin.'::Content.image'),
            'title'       => trans($this->plugin->pathPlugin.'::Content.title'),
            'category_id' => trans($this->plugin->pathPlugin.'::Content.category_id'),
            'status'      => trans($this->plugin->pathPlugin.'::Content.status'),
            'sort'        => trans($this->plugin->pathPlugin.'::Content.sort'),
            'action'      => trans($this->plugin->pathPlugin.'::Content.admin.action'),
        ];
        $sort_order = request('sort_order') ?? 'id_desc';
        $keyword = request('keyword') ?? '';
        $arrSort = [
            'id__desc'    => trans($this->plugin->pathPlugin.'::Content.admin.sort_order.id_desc'),
            'id__asc'     => trans($this->plugin->pathPlugin.'::Content.admin.sort_order.id_asc'),
            'title__desc' => trans($this->plugin->pathPlugin.'::Content.admin.sort_order.title_desc'),
            'title__asc'  => trans($this->plugin->pathPlugin.'::Content.admin.sort_order.title_asc'),
        ];

        $dataSearch = [
            'keyword'    => $keyword,
            'sort_order' => $sort_order,
            'arrSort'    => $arrSort,
        ];
        $dataTmp = (new AdminCmsContent)->getContentListAdmin($dataSearch);

        $dataTr = [];
        foreach ($dataTmp as $key => $row) {
            $dataTr[] = [
                'id' => $row['id'],
                'image' => sc_image_render($row->getThumb(), '50px', '50px', $row['title']),
                'title' => $row['title'],
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,8 +48,8 @@
             'sort'        => trans($this->plugin->pathPlugin.'::Content.sort'),
             'action'      => trans($this->plugin->pathPlugin.'::Content.admin.action'),
         ];
-        $sort_order = request('sort_order') ?? 'id_desc';
-        $keyword = request('keyword') ?? '';
+        $sort_order = sc_clean(request('sort_order') ?? 'id_desc');
+        $keyword    = sc_clean(request('keyword') ?? '');
         $arrSort = [
             'id__desc'    => trans($this->plugin->pathPlugin.'::Content.admin.sort_order.id_desc'),
             'id__asc'     => trans($this->plugin->pathPlugin.'::Content.admin.sort_order.id_asc'),
```
