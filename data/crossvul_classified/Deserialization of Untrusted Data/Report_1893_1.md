# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 1893_1
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1893_1`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 76-116 of the vulnerable file.

import io.onedev.server.web.page.project.issues.detail.IssueCommitsPage;
import io.onedev.server.web.page.project.issues.detail.IssuePullRequestsPage;
import io.onedev.server.web.page.project.issues.list.ProjectIssueListPage;
import io.onedev.server.web.page.project.issues.milestones.MilestoneDetailPage;
import io.onedev.server.web.page.project.issues.milestones.MilestoneEditPage;
import io.onedev.server.web.page.project.issues.milestones.MilestoneListPage;
import io.onedev.server.web.page.project.issues.milestones.NewMilestonePage;
import io.onedev.server.web.page.project.pullrequests.InvalidPullRequestPage;
import io.onedev.server.web.page.project.pullrequests.ProjectPullRequestsPage;
import io.onedev.server.web.page.project.pullrequests.create.NewPullRequestPage;
import io.onedev.server.web.page.project.pullrequests.detail.activities.PullRequestActivitiesPage;
import io.onedev.server.web.page.project.pullrequests.detail.changes.PullRequestChangesPage;
import io.onedev.server.web.page.project.pullrequests.detail.codecomments.PullRequestCodeCommentsPage;
import io.onedev.server.web.page.project.pullrequests.detail.mergepreview.MergePreviewPage;
import io.onedev.server.web.page.project.setting.authorization.ProjectAuthorizationsPage;
import io.onedev.server.web.page.project.setting.avatar.AvatarEditPage;
import io.onedev.server.web.page.project.setting.branchprotection.BranchProtectionsPage;
import io.onedev.server.web.page.project.setting.build.ActionAuthorizationsPage;
import io.onedev.server.web.page.project.setting.build.BuildPreservationsPage;
import io.onedev.server.web.page.project.setting.build.JobSecretsPage;
import io.onedev.server.web.page.project.setting.tagprotection.TagProtectionsPage;
import io.onedev.server.web.page.project.setting.webhook.WebHooksPage;
import io.onedev.server.web.page.project.stats.ProjectContribsPage;
import io.onedev.server.web.page.project.stats.SourceLinesPage;
import io.onedev.server.web.page.project.tags.ProjectTagsPage;
import io.onedev.server.web.page.pullrequests.PullRequestListPage;
import io.onedev.server.web.page.simple.error.PageNotFoundErrorPage;
import io.onedev.server.web.page.simple.security.LoginPage;
import io.onedev.server.web.page.simple.security.LogoutPage;
import io.onedev.server.web.page.simple.security.PasswordResetPage;
import io.onedev.server.web.page.simple.security.SignUpPage;
import io.onedev.server.web.page.simple.serverinit.ServerInitPage;
import io.onedev.server.web.resource.ArchiveResourceReference;
import io.onedev.server.web.resource.ArtifactResourceReference;
import io.onedev.server.web.resource.AttachmentResourceReference;
import io.onedev.server.web.resource.BuildLogResourceReference;
import io.onedev.server.web.resource.RawBlobResourceReference;
import io.onedev.server.web.resource.ServerLogResourceReference;
import io.onedev.server.web.resource.SvgSpriteResourceReference;

public class BaseUrlMapper extends CompoundRequestMapper {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -93,6 +93,7 @@
 import io.onedev.server.web.page.project.setting.build.ActionAuthorizationsPage;
 import io.onedev.server.web.page.project.setting.build.BuildPreservationsPage;
 import io.onedev.server.web.page.project.setting.build.JobSecretsPage;
+import io.onedev.server.web.page.project.setting.general.GeneralProjectSettingPage;
 import io.onedev.server.web.page.project.setting.tagprotection.TagProtectionsPage;
 import io.onedev.server.web.page.project.setting.webhook.WebHooksPage;
 import io.onedev.server.web.page.project.stats.ProjectContribsPage;
@@ -260,7 +261,7 @@
 		add(new DynamicPathPageMapper("projects/${project}/builds/${build}/artifacts", BuildArtifactsPage.class));
 		add(new DynamicPathPageMapper("projects/${project}/builds/${build}/invalid", InvalidBuildPage.class));
 		
-		add(new DynamicPathPageMapper("projects/${project}/settings/general", GeneralSecuritySettingPage.class));
+		add(new DynamicPathPageMapper("projects/${project}/settings/general", GeneralProjectSettingPage.class));
 		add(new DynamicPathPageMapper("projects/${project}/settings/authorizations", ProjectAuthorizationsPage.class));
 		add(new DynamicPathPageMapper("projects/${project}/settings/avatar-edit", AvatarEditPage.class));
 		add(new DynamicPathPageMapper("projects/${project}/settings/branch-protection", BranchProtectionsPage.class));
```
