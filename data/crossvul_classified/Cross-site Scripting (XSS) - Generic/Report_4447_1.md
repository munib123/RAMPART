# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4447_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4447_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 183-223 of the vulnerable file.

        $message = [
            'name.required' => trans('validation.required', ['attribute' => trans('front.contact_form.name')]),
            'content.required' => trans('validation.required', ['attribute' => trans('front.contact_form.content')]),
            'title.required' => trans('validation.required', ['attribute' => trans('front.contact_form.title')]),
            'email.required' => trans('validation.required', ['attribute' => trans('front.contact_form.email')]),
            'email.email' => trans('validation.email', ['attribute' => trans('front.contact_form.email')]),
            'phone.required' => trans('validation.required', ['attribute' => trans('front.contact_form.phone')]),
            'phone.regex' => trans('validation.phone', ['attribute' => trans('front.contact_form.phone')]),
        ];

        if(sc_captcha_method() && in_array('contact', sc_captcha_page())) {
            $data['captcha_field'] = $data[sc_captcha_method()->getField()] ?? '';
            $validate['captcha_field'] = ['required', 'string', new \SCart\Core\Rules\CaptchaRule];
        }
        $validator = \Illuminate\Support\Facades\Validator::make($data, $validate, $message);
        if ($validator->fails()) {
            return redirect()->back()
                        ->withErrors($validator)
                        ->withInput();
        }
        //Send email
        $data['content'] = str_replace("\n", "<br>", $data['content']);

        if (sc_config('contact_to_admin')) {
            $checkContent = (new ShopEmailTemplate)
                ->where('group', 'contact_to_admin')
                ->where('status', 1)
                ->first();
            if ($checkContent) {
                $content = $checkContent->text;
                $dataFind = [
                    '/\{\{\$title\}\}/',
                    '/\{\{\$name\}\}/',
                    '/\{\{\$email\}\}/',
                    '/\{\{\$phone\}\}/',
                    '/\{\{\$content\}\}/',
                ];
                $dataReplace = [
                    $data['title'],
                    $data['name'],
                    $data['email'],
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -200,6 +200,9 @@
                         ->withErrors($validator)
                         ->withInput();
         }
+        // Process escape
+        $data = sc_clean($data);
+        
         //Send email
         $data['content'] = str_replace("\n", "<br>", $data['content']);
 
```
