# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in java
**Pair ID:** 510_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `510_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```java
Lines 40-80 of the vulnerable file.

    ILLEGAL_USERNAME(1011), //username 错误
    ILLEGAL_PASSWORD(1012), //password 错误

    SCOPE_OUT_OF_RANGE(2010), //scope超出范围

    UNAUTHORIZED_CLIENT(4010), //无权限
    EXPIRED_TOKEN(4011), //TOKEN过期
    INVALID_TOKEN(4012), //TOKEN已失效
    UNSUPPORTED_GRANT_TYPE(4013), //不支持的认证类型
    UNSUPPORTED_RESPONSE_TYPE(4014), //不支持的响应类型

    EXPIRED_CODE(4015), //AUTHORIZATION_CODE过期
    EXPIRED_REFRESH_TOKEN(4020), //REFRESH_TOKEN过期

    CLIENT_DISABLED(4016),//客户端已被禁用

    CLIENT_NOT_EXIST(4040),//客户端不存在

    USER_NOT_EXIST(4041),//客户端不存在

    ACCESS_DENIED(503), //访问被拒绝

    OTHER(5001), //其他错误 ;

    PARSE_RESPONSE_ERROR(5002),//解析返回结果错误

    SERVICE_ERROR(5003); //服务器返回错误信息


    private final String message;
    private final int    code;
    static final Map<Integer, ErrorType> codeMapping = Arrays.stream(ErrorType.values())
            .collect(Collectors.toMap(ErrorType::code, type -> type));

    ErrorType(int code) {
        this.code = code;
        message = this.name().toLowerCase();
    }

    ErrorType(int code, String message) {
        this.message = message;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,6 +57,8 @@
 
     USER_NOT_EXIST(4041),//客户端不存在
 
+    STATE_ERROR(4042), //stat错误
+
     ACCESS_DENIED(503), //访问被拒绝
 
     OTHER(5001), //其他错误 ;
```
