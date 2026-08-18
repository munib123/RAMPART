# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in java
**Pair ID:** 4347_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4347_3`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```java
Lines 174-214 of the vulnerable file.

					.setIssuer("dpppt-sdk-backend").setSubject(originalJWT.getSubject())
					.setExpiration(Date
							.from(delayedKeyDate.atStartOfDay().toInstant(ZoneOffset.UTC).plus(Duration.ofHours(48))))
					.claim("scope", "currentDayExposed").claim("delayedKeyDate", gaenRequest.getDelayedKeyDate());
			if (originalJWT.containsClaim("fake")) {
				jwtBuilder.claim("fake", originalJWT.getClaim("fake"));
			}
			String jwt = jwtBuilder.signWith(secondDayKey).compact();
			responseBuilder.header("Authorization", "Bearer " + jwt);
			responseBuilder.header("X-Exposed-Token", "Bearer " + jwt);
		}
		Callable<ResponseEntity<String>> cb = () -> {
			normalizeRequestTime(now);
			return responseBuilder.body("OK");
		};
		return cb;
	}

	@PostMapping(value = "/exposednextday")
	@Loggable
	@Transactional
	@Operation(description = "Allows the client to send the last exposed key of the infection to the backend server. The JWT must come from a previous call to /exposed")
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "The exposed key has been stored in the backend"),
			@ApiResponse(responseCode = "400", description = 
					"- Ivnalid base64 encoded Temporary Exposure Key" +
					"- TEK-date does not match delayedKeyDAte claim in Jwt" +
					"- TEK has negative rolling period"),
			@ApiResponse(responseCode = "403", description = "No delayedKeyDate claim in authentication") })
	public @ResponseBody Callable<ResponseEntity<String>> addExposedSecond(
			@Valid @RequestBody @Parameter(description = "The last exposed key of the user") GaenSecondDay gaenSecondDay,
			@RequestHeader(value = "User-Agent") @Parameter(description = "App Identifier (PackageName/BundleIdentifier) + App-Version + OS (Android/iOS) + OS-Version", example = "ch.ubique.android.starsdk;1.0;iOS;13.3") String userAgent,
			@AuthenticationPrincipal @Parameter(description = "JWT token that can be verified by the backend server, must have been created by /v1/gaen/exposed and contain the delayedKeyDate") Object principal) {
		var now = Instant.now().toEpochMilli();

		if (!validationUtils.isValidBase64Key(gaenSecondDay.getDelayedKey().getKeyData())) {
			return () -> new ResponseEntity<>("No valid base64 key", HttpStatus.BAD_REQUEST);
		}
		if (principal instanceof Jwt && !((Jwt) principal).containsClaim("delayedKeyDate")) {
			return () -> ResponseEntity.status(HttpStatus.FORBIDDEN).body("claim does not contain delayedKeyDate");
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -191,6 +191,7 @@
 
 	@PostMapping(value = "/exposednextday")
 	@Loggable
+	@ResponseRetention(time = "application.response.retention.time.exposednextday")
 	@Transactional
 	@Operation(description = "Allows the client to send the last exposed key of the infection to the backend server. The JWT must come from a previous call to /exposed")
 	@ApiResponses(value = {
```
