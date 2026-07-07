# HackerOne Report: Staff members with no permission to  access domains can access them.
**Report ID:** 96855
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Hi , I have found that if a staff member has a permission to access settings but has no permissions to access domains he can bypass this by just going to: `*store.myshopify.com/admin/settings/domains` .

in the side menu the `domains` tab will be disabled and the user shouldn't be able to access it,but he can access it by just going the domains page url.

#Steps to reproduce:
1. Add a new staff member and limit his access o `settings` only , and don't check the `domains` option , so the member should only have access to settings and shouldn't have access to domains.
2. Logout then login with the staff member and go to: `*yourstore.myshopify.com/admin/settings/domains` and you'll be able to add , delete and modify domains.

Thanks

## Discussion & Remediation Timeline
