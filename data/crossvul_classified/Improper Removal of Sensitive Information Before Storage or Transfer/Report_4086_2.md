# CrossVul Fix Pair: Improper Removal of Sensitive Information Before Storage or Transfer in php
**Pair ID:** 4086_2
**Vulnerability Class:** Improper Removal of Sensitive Information Before Storage or Transfer
**CWE:** CWE-212
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4086_2`)

## Vulnerability Information & PoC

## Description
Improper Removal of Sensitive Information Before Storage or Transfer - Resources that may contain sensitive data include documents, packets, messages, databases, etc.

## Vulnerable Code
```php
Lines 41-81 of the vulnerable file.


        $this->client = $client ?? HttpClient::create();
    }

    public function handle(Request $request, $type = HttpKernelInterface::MASTER_REQUEST, $catch = true): Response
    {
        $headers = $this->getHeaders($request);
        $body = '';
        if (null !== $part = $this->getBody($request)) {
            $headers = array_merge($headers, $part->getPreparedHeaders()->toArray());
            $body = $part->bodyToIterable();
        }
        $response = $this->client->request($request->getMethod(), $request->getUri(), [
            'headers' => $headers,
            'body' => $body,
            'max_redirects' => 0,
        ] + $request->attributes->get('http_client_options', []));

        $response = new Response($response->getContent(!$catch), $response->getStatusCode(), $response->getHeaders(!$catch));

        $response->headers = new class($response->headers->all()) extends ResponseHeaderBag {
            protected function computeCacheControlValue(): string
            {
                return $this->getCacheControlHeader(); // preserve the original value
            }
        };

        return $response;
    }

    private function getBody(Request $request): ?AbstractPart
    {
        if (\in_array($request->getMethod(), ['GET', 'HEAD'])) {
            return null;
        }

        if (!class_exists(AbstractPart::class)) {
            throw new \LogicException('You cannot pass non-empty bodies as the Mime component is not installed. Try running "composer require symfony/mime".');
        }

        if ($content = $request->getContent()) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,6 +58,10 @@
 
         $response = new Response($response->getContent(!$catch), $response->getStatusCode(), $response->getHeaders(!$catch));
 
+        $response->headers->remove('X-Body-File');
+        $response->headers->remove('X-Body-Eval');
+        $response->headers->remove('X-Content-Digest');
+
         $response->headers = new class($response->headers->all()) extends ResponseHeaderBag {
             protected function computeCacheControlValue(): string
             {
```
