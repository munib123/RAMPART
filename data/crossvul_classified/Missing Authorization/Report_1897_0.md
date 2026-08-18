# CrossVul Fix Pair: Missing Authorization in java
**Pair ID:** 1897_0
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1897_0`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```java
Lines 95-135 of the vulnerable file.

	public static final String AUTH_SOURCE_SSO_PROVIDER = "SSO Provider: ";
	
	private static ThreadLocal<Stack<User>> stack =  new ThreadLocal<Stack<User>>() {

		@Override
		protected Stack<User> initialValue() {
			return new Stack<User>();
		}
	
	};
	
	@Column(unique=true, nullable=false)
    private String name;

    @Column(length=1024, nullable=false)
	@JsonView(DefaultView.class)
    private String password;

	private String fullName;
	
	@Embedded
	private SsoInfo ssoInfo = new SsoInfo();
	
	@Column(unique=true, nullable=false)
	private String email;
	
	@Column(unique=true, nullable=false)
	private String accessToken = RandomStringUtils.randomAlphanumeric(ACCESS_TOKEN_LEN);
	
	@OneToMany(mappedBy="user", cascade=CascadeType.REMOVE)
	@Cache(usage=CacheConcurrencyStrategy.READ_WRITE)
	private Collection<UserAuthorization> authorizations = new ArrayList<>();
	
	@OneToMany(mappedBy="user", cascade=CascadeType.REMOVE)
	@Cache(usage=CacheConcurrencyStrategy.READ_WRITE)
	private Collection<Membership> memberships = new ArrayList<>();
	
	@OneToMany(mappedBy="user", cascade=CascadeType.REMOVE)
	private Collection<PullRequestReview> pullRequestReviews = new ArrayList<>();
	
	@OneToMany(mappedBy="user", cascade=CascadeType.REMOVE)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -112,6 +112,7 @@
 
 	private String fullName;
 	
+	@JsonView(DefaultView.class)
 	@Embedded
 	private SsoInfo ssoInfo = new SsoInfo();
 	
@@ -119,6 +120,7 @@
 	private String email;
 	
 	@Column(unique=true, nullable=false)
+	@JsonView(DefaultView.class)
 	private String accessToken = RandomStringUtils.randomAlphanumeric(ACCESS_TOKEN_LEN);
 	
 	@OneToMany(mappedBy="user", cascade=CascadeType.REMOVE)
```
