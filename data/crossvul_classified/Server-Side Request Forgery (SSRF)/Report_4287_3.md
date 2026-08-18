# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in yaml
**Pair ID:** 4287_3
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** yaml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4287_3`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```yaml
Lines 63-89 of the vulnerable file.

    overdue_alert_dept_manager: 1
    overdue_alert_dept_members: 0
    assigned_alert_active: 1
    assigned_alert_staff: 1
    assigned_alert_team_lead: 0
    assigned_alert_team_members: 0
    auto_claim_tickets: 1
    auto_refer_closed: 1
    collaborator_ticket_visibility: 1
    require_topic_to_close: 0
    show_related_tickets: 1
    show_assigned_tickets: 1
    show_answered_tickets: 0
    hide_staff_name: 0
    disable_agent_collabs: 0
    overlimit_notice_active: 0
    email_attachments: 1
    ticket_number_format: '######'
    ticket_sequence_id: 0
    queue_bucket_counts: 0
    task_number_format: '#'
    task_sequence_id: 2
    log_level: 2
    log_graceperiod: 12
    client_registration: 'public'
    default_ticket_queue: 1
    embedded_domain_whitelist: 'youtube.com, dailymotion.com, vimeo.com, player.vimeo.com, web.microsoftstream.com'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -80,6 +80,7 @@
     ticket_number_format: '######'
     ticket_sequence_id: 0
     queue_bucket_counts: 0
+    allow_external_images: 1
     task_number_format: '#'
     task_sequence_id: 2
     log_level: 2
```
