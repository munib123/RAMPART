# HackerOne Report: login to any user's cashier account and full account information disclosure
**Report ID:** 98247
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Hi , I have found an  issue allowing an attacker to login to any user's cashier account and view sensitive user information by just knowing the user account ID.
#Steps to reproduce:
1. open 2 browsers and create 2 accounts , login with each account on a browser.
2. let's call account 1 , the victim and account 2 is the attacker.
3. from the victim account , make sure you are using real account and then go to https://www.binary.com/cashier then click **Deposit** then click **Continue**. 

4. From the attacker account go to https://www.binary.com/cashier then click **Deposit** then click **Continue**. 
5. Now you'll see your cashier account , inspect the page elements using your browser inspector then find the `<iframe>` tag with the id attribute **cashiercont**. it will look like this : 

```
<iframe src="https://cashier.binary.com/login.asp?Sportsbook=Binary (CR) SA USD&amp;PIN=CR342435&amp;Lang=en&amp;Password=0e552ae717a1d08cb147f132a31676559e3273ef&amp;Secret=1328d47abeda2b672b6424093c4dbc76&amp;Action=DEPOSIT" frameborder="0" width="100%" height="2000" id="cashiercont" scrolling="auto" style="padding:0px;margin:0px;"></iframe>
```
6. Edit the `<iframe>` element and Change the `PIN` parameter value to the victim account id value  so it should be like this after the edit:

```
<iframe src="https://cashier.binary.com/login.asp?Sportsbook=Binary (CR) SA USD&amp;PIN=<VICTIM_ACCOUNT_ID>&amp;Lang=en&amp;Password=0e552ae717a1d08cb147f132a31676559e3273ef&amp;Secret=1328d47abeda2b672b6424093c4dbc76&amp;Action=DEPOSIT" frameborder="0" width="100%" height="2000" id="cashiercont" scrolling="auto" style="padding:0px;margin:0px;"></iframe>
```
7. Now you have successfully logged in the victim's cashier account , to view the victim account details , click the **cashier** button then next to the **customer name** click the _view_ link and you'll see all the account details of the victim , including _Full name_ , _email_ and _phone number_ which are the most sensitive here since they can be used in phishing.

Please tell me if you are having any issue reproducing this.
Thanks

## Discussion & Remediation Timeline
