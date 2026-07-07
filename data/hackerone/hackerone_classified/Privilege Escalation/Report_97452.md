# HackerOne Report: Staff members with no permission can access to the files, uploaded by the administrator
**Report ID:** 97452
**Vulnerability Class:** Privilege Escalation

## Vulnerability Information & PoC
Staff members with no permission can access to the files, uploaded by the administrator

### Test #1 
If the member has access only to the section  Products, Inventory, & Collections
1. Go to the Products -> Product Name -> Description
2. Click the button -> Add Image
3. In the section Uploaded images are all files uploded by the admin, so we can simply add them or download (screenshot attached)
4. Uploded images are in the section Settings -> Files (but we don't have access there)

### Test #2
If the member has NO access to the ALL sections
1. So we can not go to the page Products but....
2. Lets go here https://*.myshopify.com/admin/rte/assets
3. And we will see all files uploaded by admin (screenshot attached)
4. On this page we can simply find links for admin files


## Discussion & Remediation Timeline
