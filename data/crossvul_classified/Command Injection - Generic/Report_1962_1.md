# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in typescript
**Pair ID:** 1962_1
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1962_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```typescript
Lines 1-21 of the vulnerable file.

import { exec, execSync } from 'child_process';

type Input = { ref: string; path: string };

const createLoadError = (error: any) => new Error('Unable to load file from git: ' + error);
const createCommand = ({ ref, path }: Input) => {
  return `git show ${ref}:${path}`;
};

/**
 * @internal
 */
export async function loadFromGit(input: Input): Promise<string | never> {
  try {
    return await new Promise((resolve, reject) => {
      exec(createCommand(input), { encoding: 'utf-8', maxBuffer: 1024 * 1024 * 1024 }, (error, stdout) => {
        if (error) {
          reject(error);
        } else {
          resolve(stdout);
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,10 +1,10 @@
-import { exec, execSync } from 'child_process';
+import { execFile, execFileSync } from 'child_process';
 
 type Input = { ref: string; path: string };
 
 const createLoadError = (error: any) => new Error('Unable to load file from git: ' + error);
-const createCommand = ({ ref, path }: Input) => {
-  return `git show ${ref}:${path}`;
+const createCommand = ({ ref, path }: Input): string[] => {
+  return ['show', `${ref}:${path}`];
 };
 
 /**
@@ -13,7 +13,7 @@
 export async function loadFromGit(input: Input): Promise<string | never> {
   try {
     return await new Promise((resolve, reject) => {
-      exec(createCommand(input), { encoding: 'utf-8', maxBuffer: 1024 * 1024 * 1024 }, (error, stdout) => {
+      execFile('git', createCommand(input), { encoding: 'utf-8', maxBuffer: 1024 * 1024 * 1024 }, (error, stdout) => {
         if (error) {
           reject(error);
         } else {
@@ -31,7 +31,7 @@
  */
 export function loadFromGitSync(input: Input): string | never {
   try {
-    return execSync(createCommand(input), { encoding: 'utf-8' });
+    return execFileSync('git', createCommand(input), { encoding: 'utf-8' });
   } catch (error) {
     throw createLoadError(error);
   }
```
