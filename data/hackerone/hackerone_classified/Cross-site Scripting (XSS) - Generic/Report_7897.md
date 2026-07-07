# HackerOne Report: HTML/Javascript possible in "Discussion" section of reviews
**Report ID:** 7897
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
It's possible to enter HTML code and/or execute javascript code in the "Discussion" section for review.

To reproduce:

- Enter a new phrase in a project.
- Login as a different user and provide a new translation for the phrase.
- Switch back to the user that created the project and check the review phrase.
- In the discussion section, enter a new message containing HTML/Javascript.
- Open the link the is shown there and observe that HTML is not filtered and that javascript can be executed.

## Discussion & Remediation Timeline
