# CrossVul Fix Pair: Missing Authorization in typescript
**Pair ID:** 4470_0
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4470_0`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```typescript
Lines 635-675 of the vulnerable file.

  }

  return result.allProjects;
}

export async function getProjectByName(project: string): Promise<any> {
  const result = await graphqlapi.query(`
    {
      project:projectByName(name: "${project}") {
        ...${projectFragment}
      }
    }
  `);

  if (!result || !result.project) {
    throw new ProjectNotFound(`Cannot find project ${project}`);
  }

  return result.project;
}

export async function getMicrosoftTeamsInfoForProject(
  project: string, contentType = 'DEPLOYMENT'
): Promise<any[]> {
  const notificationsFragment = graphqlapi.createFragment(`
    fragment on NotificationMicrosoftTeams {
      webhook
      contentType
      notificationSeverityThreshold
    }
  `);

  const result = await graphqlapi.query(`
    {
      project:projectByName(name: "${project}") {
        microsoftTeams: notifications(type: MICROSOFTTEAMS, contentType: ${contentType}) {
          ...${notificationsFragment}
        }
      }
    }
  `);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -652,6 +652,23 @@
 
   return result.project;
 }
+
+export const allProjectsInGroup = (groupInput: {
+  id?: string;
+  name?: string;
+}): Promise<any[]> =>
+  graphqlapi.query(
+    `
+    query($groupInput: GroupInput!) {
+      allProjectsInGroup(input: $groupInput) {
+        ...${projectFragment}
+      }
+    }
+  `,
+    {
+      groupInput
+    }
+  );
 
 export async function getMicrosoftTeamsInfoForProject(
   project: string, contentType = 'DEPLOYMENT'
```
