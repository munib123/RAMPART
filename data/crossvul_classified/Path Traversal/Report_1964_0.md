# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 1964_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1964_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 416-456 of the vulnerable file.

            $exportFile = PIMCORE_SYSTEM_TEMP_DIRECTORY . '/report-export-' . uniqid() . '.csv';
            @unlink($exportFile);
        }

        $fp = fopen($exportFile, 'a');

        if ($includeHeaders) {
            fputcsv($fp, $fields, ';');
        }

        foreach ($result['data'] as $row) {
            fputcsv($fp, array_values($row), ';');
        }

        fclose($fp);

        $progress = $result['total'] ? ($offset * $limit) / $result['total'] : 1;
        $progress = $progress > 1 ? 1 : $progress;

        return new JsonResponse([
            'exportFile' => $exportFile,
            'offset' => $offset,
            'progress' => $progress,
            'finished' => empty($result['data']) || count($result['data']) < $limit,
        ]);
    }

    /**
     * @Route("/download-csv", name="pimcore_admin_reports_customreport_downloadcsv", methods={"GET"})
     *
     * @param Request $request
     *
     * @return BinaryFileResponse
     */
    public function downloadCsvAction(Request $request)
    {
        $this->checkPermission('reports');
        if ($exportFile = $request->get('exportFile')) {
            $response = new BinaryFileResponse($exportFile);
            $response->headers->set('Content-Type', 'text/csv; charset=UTF-8');
            $response->setContentDisposition(ResponseHeaderBag::DISPOSITION_ATTACHMENT, 'export.csv');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -433,7 +433,7 @@
         $progress = $progress > 1 ? 1 : $progress;
 
         return new JsonResponse([
-            'exportFile' => $exportFile,
+            'exportFile' => basename($exportFile),
             'offset' => $offset,
             'progress' => $progress,
             'finished' => empty($result['data']) || count($result['data']) < $limit,
@@ -451,6 +451,7 @@
     {
         $this->checkPermission('reports');
         if ($exportFile = $request->get('exportFile')) {
+            $exportFile = PIMCORE_SYSTEM_TEMP_DIRECTORY . '/' . basename($exportFile);
             $response = new BinaryFileResponse($exportFile);
             $response->headers->set('Content-Type', 'text/csv; charset=UTF-8');
             $response->setContentDisposition(ResponseHeaderBag::DISPOSITION_ATTACHMENT, 'export.csv');
```
