# CrossVul Fix Pair: Weak Password Recovery Mechanism for Forgotten Password in php
**Pair ID:** 34_0
**Vulnerability Class:** Weak Password Recovery Mechanism for Forgotten Password
**CWE:** CWE-640
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `34_0`)

## Vulnerability Information & PoC

## Description
Weak Password Recovery Mechanism for Forgotten Password - It is common for an application to have a mechanism that provides a means for a user to gain access to their account in the event they forget their password.

## Vulnerable Code
```php
Lines 246-286 of the vulnerable file.


		Log::write('requested password change', LogSeverity::Notice, $u->id);

		//set variables for template
		$vars = array(
			'name'=>$u->name
			,'email'=>$u->email

			,'website_title'=>Setting::value('website_title', CS_PRODUCT_NAME)
			,'reset_link'=>site_url('administration/auth/resetpass/'.$u->id.'/'.$u->key)
			,'site_url'=>site_url()
		);

		//get email template
		$template = file_get_contents(APPPATH . "templates/forgot_password.html");
		$template = __($template, null, 'email');
		$template .= "<br />\n<br />\n<br />\n" . __(file_get_contents(APPPATH . "templates/signature.html"), null, 'email');
		$template = parse_template($template, $vars);

		//send email
		$this->email->to("$email");
		$this->email->subject(__("%s password reset", Setting::value('website_title', CS_PRODUCT_NAME), 'email'));
		$this->email->message($template);
		$this->email->set_alt_message(strip_tags($template));

		$from = Setting::value("default_email", false);

		if (empty($from))
			$from = "noreply@".get_domain_name(true);

		$this->email->from($from);

		$sent = $this->email->send();

		if ($sent)
			$this->templatemanager->notify_next(__("Please check your e-mail for further information."), "notice", __("Notice"));
		else
			$this->templatemanager->notify_next(__("Activation e-mail could not be sent!"), "error", __("Error"));

		redirect("administration/auth/login");
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -263,7 +263,7 @@
 		$template = parse_template($template, $vars);
 
 		//send email
-		$this->email->to("$email");
+		$this->email->to($u->email);
 		$this->email->subject(__("%s password reset", Setting::value('website_title', CS_PRODUCT_NAME), 'email'));
 		$this->email->message($template);
 		$this->email->set_alt_message(strip_tags($template));
```
