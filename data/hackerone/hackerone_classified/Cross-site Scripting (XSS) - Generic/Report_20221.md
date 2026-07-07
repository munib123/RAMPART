# HackerOne Report: Cross Site Scripting (Stored) 
**Report ID:** 20221
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Occurred in the URL : https://store.ellislab.com/billing
After adding a product to the cart proceed to add the billing and card information and in the card fields give your card details respectively and in the fields 
1. First name
2. Last name
3. Street Address
4. Apt/Suite/#
5. City. 

Give the following payload : "><img src=x onerror=prompt(0);> and click on Place Order and there it goes 5 stored XSS will appear

## Discussion & Remediation Timeline
