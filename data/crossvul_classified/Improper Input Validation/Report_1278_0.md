# CrossVul Fix Pair: Improper Input Validation in csharp
**Pair ID:** 1278_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1278_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```csharp
Lines 44-84 of the vulnerable file.

        {
            if (CurrentUser == null)
            {
                return NotFound("Could not find user");
            }

            var invites = db.OrganisationInvites.Where(uc => uc.InviteEmail.ToLower() == CurrentUser.Email.ToLower() && uc.AcceptedOn == null && uc.RejectedOn == null);

            if (invites.Any() == false)
            {
                // No invites to look at, redirect to home
                return RedirectToAction("Index", "Home");
            }

            List<InvitationViewModel> viewModels = new List<InvitationViewModel>();

            foreach(var orgGrp in invites
                .Include(c => c.CreatedBy)
                .GroupBy(c => c.OrganisationId))
            {
                InvitationViewModel viewModel = new InvitationViewModel();
                
                Organisation organisation = db.Organisations.First(ba => ba.OrganisationId == orgGrp.Key);
                viewModel.OrganisationId = organisation.OrganisationId;

                viewModel.Invitees = orgGrp
                    .Select(g => g.CreatedBy.UserName)
                    .OrderBy(_ => _)
                    .Distinct()
                    .ToList();
                
                viewModel.OrganisationName = organisation.OrganisationName;
                
                viewModels.Add(viewModel);
            }

            if (viewModels.Any())
            {
                List<string> databasesMerged = new List<string>();
                List<string> databasesLost = new List<string>();
                
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,7 +61,10 @@
                 .Include(c => c.CreatedBy)
                 .GroupBy(c => c.OrganisationId))
             {
-                InvitationViewModel viewModel = new InvitationViewModel();
+                InvitationViewModel viewModel = new InvitationViewModel
+                {
+                    OrganisationInviteId = orgGrp.First().OrganisationInviteId
+                };
                 
                 Organisation organisation = db.Organisations.First(ba => ba.OrganisationId == orgGrp.Key);
                 viewModel.OrganisationId = organisation.OrganisationId;
@@ -119,22 +122,20 @@
                 return NotFound("Could not find user");
             }
 
-            var organisation = db.Organisations.FirstOrDefault(ba => ba.OrganisationId == id);
+            var invite = db.OrganisationInvites.FirstOrDefault(uc => uc.InviteEmail.ToLower() == CurrentUser.Email.ToLower() && uc.AcceptedOn == null && uc.RejectedOn == null && uc.OrganisationInviteId == id);
+
+            if (invite == null)
+            {
+                return NotFound("Invite not found");
+            }
+
+            var organisation = db.Organisations.FirstOrDefault(ba => ba.OrganisationId == invite.OrganisationId);
 
             if (organisation == null)
             {
                 return NotFound("Organisation not found");
             }
 
-            // remove other invitations to other organisations
-            db.OrganisationInvites.RemoveWhere(uc => uc.InviteEmail.ToLower() == CurrentUser.Email.ToLower() && uc.OrganisationId != id);
-
-            db.SaveChanges();
-
-            var invitationsToAccept = db.OrganisationInvites
-                .Where(uc => uc.InviteEmail == CurrentUser.Email && uc.OrganisationId == id)
-                .ToList();
-            
             List<DatabaseConnection> leave = new List<DatabaseConnection>();
             List<DatabaseConnection> migrate = new List<DatabaseConnection>();
             
@@ -173,11 +174,16 @@
             
             CurrentUser.OrganisationId = organisation.OrganisationId;
 
-            foreach (var invite in invitationsToAccept)
-            {
-                invite.AcceptedOn = DateTime.Now;
-            }
+            invite.AcceptedOn = DateTime.Now;
+            
+            // reject other invitations to other organisations
+            var invitesToReject = db.OrganisationInvites.Where(uc => uc.InviteEmail.ToLower() == CurrentUser.Email.ToLower() && uc.OrganisationInviteId != invite.OrganisationInviteId);
         
+            foreach (var inviteToReject in invitesToReject)
+            {
+                inviteToReject.RejectedOn = DateTime.Now;
+            }
+
             db.SaveChanges();
 
             return RedirectToAction("Index", "Home");
@@ -190,7 +196,13 @@
                 return NotFound("Could not find user");
             }
             
-            var invite = db.OrganisationInvites.First(i => i.InviteEmail.ToLower() == CurrentUser.Email.ToLower() && i.OrganisationId == id && i.AcceptedOn == null && i.RejectedOn == null);
+            var invite = db.OrganisationInvites.FirstOrDefault(uc => uc.InviteEmail.ToLower() == CurrentUser.Email.ToLower() && uc.AcceptedOn == null && uc.RejectedOn == null && uc.OrganisationInviteId == id);
+
+            if (invite == null)
+            {
+                return NotFound("Invite not found");
+            }
+
             invite.RejectedOn = DateTime.Now;
 
             db.SaveChanges();
```
