# CrossVul Fix Pair: Use of a Broken or Risky Cryptographic Algorithm in java
**Pair ID:** 4532_5
**Vulnerability Class:** Use of a Broken or Risky Cryptographic Algorithm
**CWE:** CWE-327
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4532_5`)

## Vulnerability Information & PoC

## Description
Use of a Broken or Risky Cryptographic Algorithm - Cryptographic algorithms are the methods by which data is scrambled to prevent observation or influence by unauthorized actors.

## Vulnerable Code
```java
Lines 167-207 of the vulnerable file.

      @RestParameter(
        name = "username",
        description = "The username.",
        isRequired = true,
        type = STRING)
    }, reponses = {
      @RestResponse(
        responseCode = SC_OK,
        description = "The user account."),
      @RestResponse(
        responseCode = SC_NOT_FOUND,
        description = "User not found")
    })
  public Response getUserAsJson(@PathParam("username") String username) throws NotFoundException {
    User user = jpaUserAndRoleProvider.loadUser(username);
    if (user == null) {
      logger.debug("Requested user not found: {}", username);
      return Response.status(SC_NOT_FOUND).build();
    }
    return Response.ok(JaxbUser.fromUser(user)).build();
  }

  @POST
  @Path("/")
  @RestQuery(
    name = "createUser",
    description = "Create a new  user",
    returnDescription = "Location of the new ressource",
    restParameters = {
      @RestParameter(
        name = "username",
        description = "The username.",
        isRequired = true,
        type = STRING),
      @RestParameter(
        name = "password",
        description = "The password.",
        isRequired = true,
        type = STRING),
      @RestParameter(
        name = "name",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -186,6 +186,26 @@
     return Response.ok(JaxbUser.fromUser(user)).build();
   }
 
+  @GET
+  @Path("users/md5.json")
+  @Produces(MediaType.APPLICATION_JSON)
+  @RestQuery(
+      name = "users-with-insecure-hashing",
+      description = "Returns a list of users which passwords are stored using MD5 hashes",
+      returnDescription = "Returns a JSON representation of the list of matching user accounts",
+      reponses = {
+      @RestResponse(
+          responseCode = SC_OK,
+          description = "The user accounts.")
+  })
+  public JaxbUserList getUserWithInsecurePasswordHashingAsJson() {
+    JaxbUserList userList = new JaxbUserList();
+    for (User user: jpaUserAndRoleProvider.findInsecurePasswordHashes()) {
+      userList.add(user);
+    }
+    return userList;
+  }
+
   @POST
   @Path("/")
   @RestQuery(
```
