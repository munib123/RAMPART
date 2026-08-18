# CrossVul Fix Pair: Missing Authorization in typescript
**Pair ID:** 4470_1
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4470_1`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```typescript
Lines 1-40 of the vulnerable file.

import axios from 'axios';
import { pathOr, propOr } from 'ramda';

const API_HOST = propOr('http://gitlab', 'GITLAB_API_HOST', process.env);
const API_TOKEN = propOr(
  'personal access token',
  'GITLAB_API_TOKEN',
  process.env
);

const options = {
  baseURL: `${API_HOST}/api/v4/`,
  timeout: 30000,
  headers: {
    'Private-Token': API_TOKEN
  }
};

const gitlabapi = axios.create(options);

class NetworkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NetworkError';
  }
}

class APIError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GitLabAPIError';
  }
}

const getRequest = async (url: string): Promise<any> => {
  try {
    const response = await gitlabapi.get(url);
    return response.data;
  } catch (error) {
    if (error.response) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,6 +17,26 @@
 };
 
 const gitlabapi = axios.create(options);
+
+export const secureGitlabSystemHooks = [
+  'group_create',
+  'group_rename',
+  'group_destroy',
+  'project_create',
+  'project_transfer',
+  'project_rename',
+  'project_update',
+  'project_destroy',
+  'user_create',
+  'user_rename',
+  'user_destroy',
+  'user_add_to_group',
+  'user_remove_from_group',
+  'user_add_to_team',
+  'user_remove_from_team',
+  'key_create',
+  'key_destroy',
+];
 
 class NetworkError extends Error {
   constructor(message: string) {
```
