# HackerOne Report: Weak random number generator used in concrete/authentication/concrete/controller.php
**Report ID:** 31171
**Vulnerability Class:** Cryptographic Issues - Generic

## Vulnerability Information & PoC
```php

    private function genString($a = 20)
    {
        $o = '';
        $chars = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+{}|":<>?\'\\';
        $l = strlen($chars);
        while ($a--) {
            $o .= substr($chars, rand(0, $l), 1);
        }
        return md5($o);
    }
```

Using substr(rand()) then running md5() on the output would be better replaced by using bin2hex() and either openssl_random_pseudo_bytes($a) or mcrypt_create_iv($a, MCRYPT_DEV_URANDOM)

For example:

```php
    private function genString($a = 20)
    {
        if (function_exists('mcrypt_create_iv')) {
            return bin2hex(mcrypt_create_iv($a, MCRYPT_DEV_URANDOM);
        }
        return bin2hex(openssl_random_pseudo_bytes($a));
    }
```

## Discussion & Remediation Timeline
