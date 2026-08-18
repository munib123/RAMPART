# CrossVul Fix Pair: Use of a One-Way Hash without a Salt in java
**Pair ID:** 1902_0
**Vulnerability Class:** Use of a One-Way Hash without a Salt
**CWE:** CWE-759
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1902_0`)

## Vulnerability Information & PoC

## Description
Use of a One-Way Hash without a Salt - This makes it easier for attackers to pre-compute the hash value using dictionary attack techniques such as rainbow tables.

## Vulnerable Code
```java
Lines 1-41 of the vulnerable file.

package com.bijay.onlinevotingsystem.controller;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.bijay.onlinevotingsystem.dao.AdminDao;
import com.bijay.onlinevotingsystem.dao.AdminDaoImpl;

@WebServlet("/aLoginController")
public class AdminLoginController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	AdminDao adminDao = new AdminDaoImpl();
	SHA256 sha = new SHA256();

	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		HttpSession session = request.getSession();
		session.invalidate();

		RequestDispatcher rd = request.getRequestDispatcher("adminlogin.jsp");
		request.setAttribute("loggedOutMsg", "Log Out Successful");
		rd.include(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		// to get values from the login page
		String userName = request.getParameter("aname");
		String password = sha.getSHA(request.getParameter("pass"));
		// String password = request.getParameter("pass");
		String rememberMe = request.getParameter("remember-me");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,7 +18,6 @@
 public class AdminLoginController extends HttpServlet {
 	private static final long serialVersionUID = 1L;
 	AdminDao adminDao = new AdminDaoImpl();
-	SHA256 sha = new SHA256();
 
 	protected void doGet(HttpServletRequest request, HttpServletResponse response)
 			throws ServletException, IOException {
@@ -36,7 +35,7 @@
 
 		// to get values from the login page
 		String userName = request.getParameter("aname");
-		String password = sha.getSHA(request.getParameter("pass"));
+		String password = request.getParameter("pass");
 		// String password = request.getParameter("pass");
 		String rememberMe = request.getParameter("remember-me");
 
```
