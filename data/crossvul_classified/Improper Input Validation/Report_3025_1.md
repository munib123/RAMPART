# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3025_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3025_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1580-1620 of the vulnerable file.

    ippAddString(con->request, IPP_TAG_JOB, IPP_TAG_NAME, "job-name", NULL, "Untitled");
  else if ((attr->value_tag != IPP_TAG_NAME &&
            attr->value_tag != IPP_TAG_NAMELANG) ||
           attr->num_values != 1)
  {
    send_ipp_status(con, IPP_ATTRIBUTES,
                    _("Bad job-name value: Wrong type or count."));
    if ((attr = ippCopyAttribute(con->response, attr, 0)) != NULL)
      attr->group_tag = IPP_TAG_UNSUPPORTED_GROUP;
    return (NULL);
  }
  else if (!ippValidateAttribute(attr))
  {
    send_ipp_status(con, IPP_ATTRIBUTES, _("Bad job-name value: %s"),
                    cupsLastErrorString());
    if ((attr = ippCopyAttribute(con->response, attr, 0)) != NULL)
      attr->group_tag = IPP_TAG_UNSUPPORTED_GROUP;
    return (NULL);
  }

  if ((job = cupsdAddJob(priority, printer->name)) == NULL)
  {
    send_ipp_status(con, IPP_INTERNAL_ERROR,
                    _("Unable to add job for destination \"%s\"."),
		    printer->name);
    return (NULL);
  }

  job->dtype   = printer->type & (CUPS_PRINTER_CLASS | CUPS_PRINTER_REMOTE);
  job->attrs   = con->request;
  job->dirty   = 1;
  con->request = ippNewRequest(job->attrs->request.op.operation_id);

  cupsdMarkDirty(CUPSD_DIRTY_JOBS);

  add_job_uuid(job);
  apply_printer_defaults(printer, job);

  attr = ippFindAttribute(job->attrs, "requesting-user-name", IPP_TAG_NAME);

  if (con->username[0])
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1597,6 +1597,16 @@
     return (NULL);
   }
 
+  attr = ippFindAttribute(con->request, "requesting-user-name", IPP_TAG_NAME);
+
+  if (attr && !ippValidateAttribute(attr))
+  {
+    send_ipp_status(con, IPP_ATTRIBUTES, _("Bad requesting-user-name value: %s"), cupsLastErrorString());
+    if ((attr = ippCopyAttribute(con->response, attr, 0)) != NULL)
+      attr->group_tag = IPP_TAG_UNSUPPORTED_GROUP;
+    return (NULL);
+  }
+
   if ((job = cupsdAddJob(priority, printer->name)) == NULL)
   {
     send_ipp_status(con, IPP_INTERNAL_ERROR,
@@ -1614,8 +1624,6 @@
 
   add_job_uuid(job);
   apply_printer_defaults(printer, job);
-
-  attr = ippFindAttribute(job->attrs, "requesting-user-name", IPP_TAG_NAME);
 
   if (con->username[0])
   {
```
