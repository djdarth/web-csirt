---
layout: post
title: Visioweb.js
author: Victor Pasman
researchers:
    - Jan-Jaap Korpershoek
excerpt: "Client-side prototype pollution in Visioweb.js allows attackers to execute XSS on the client system."
---
During a penetration test, a client-side prototype pollution vulnerability was discovered in the Visioweb.js library, developed by Visio Globe. The vulnerability occurs in the `getURLParameters` function and, when combined with a gadget elsewhere in the application, can lead to DOM-based cross-site scripting (XSS).

DIVD is a CVE Numbering Authority (CNA) and has used these rights to assign the following CVE to the vulnerability included in the write-up below:
- CVE-2022-3901

The rest of this post contains the full technical write-up of the vulnerability.

## Client-side prototype pollution leading to DOM-XSS - CVE-2022-3901

- CVE: CVE-2022-3901
- Discovered by: Jan-Jaap Korpershoek
- Credits: Jan-Jaap Korpershoek (finder), Victor Pasman (DIVD, analyst)
- Products: Visioweb.js (Visio Globe), affected platforms: Windows, MacOS, Linux
- Affected versions: all versions up to and including 1.10.6
- CVSS: 7.2 (High) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N
- CWE: CWE-1321 — Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')
- CAPEC: CAPEC-588 — DOM-Based XSS
- Reference: https://csirt.divd.nl/CVE-2022-3901
- Solution: Upgrade to Visioweb 1.10.7

### Technical write-up

Prototypes are the mechanism by which JavaScript objects inherit features from one another. Each object has a prototype, which can be accessed using the `__proto__` parameter. This prototype contains fields and functions that are accessible from the object itself so if a parameter is not overridden on the object itself, the value from the prototype is used instead.

If the prototype of an object can be changed ("polluted") by user-controlled input, this is called a prototype pollution vulnerability.

Client-side prototype pollution is not, on its own, a vulnerability with direct impact. However, when paired with a "gadget" any piece of JavaScript that evaluates the user-controlled prototype value or inserts it unsafely into the DOM — it can lead to vulnerabilities such as DOM-based XSS or open redirection, potentially allowing an attacker to control JavaScript execution on the page.
The affected code path is the `getURLParameters` function, which parses URL parameters without adequately guarding against prototype pollution. This function is part of the `mapviewer-uikit` code that ships as an integral component of the Visioweb distribution — it is not an optional, standalone sample that a consumer would typically strip out. For that reason the issue is treated as affecting the product itself, across all versions up to and including 1.10.6, rather than being scoped to a detached demo. The behaviour was reproduced against the `mapviewer-uikit` code shipped in the ZIP package for VisioWeb 1.10.6.
To keep the impact assessment precise, it is worth separating what was directly demonstrated from what is conditional:

**What was demonstrated.** A proof-of-concept payload targeting `getURLParameters` confirmed the prototype pollution primitive: by supplying a crafted URL, arbitrary properties on JavaScript objects used by the page could be overwritten. This is the finding that was actually reproduced during the engagement.

**What is conditional.** Prototype pollution by itself does not execute attacker-controlled script. Escalation to DOM-based XSS (or open redirection) requires a suitable gadget — downstream code that reads the polluted value and passes it into a dangerous sink (the DOM or a JavaScript execution context). Whether that escalation is reachable depends on the specific gadgets present in a given application built on top of Visioweb, and a full end-to-end XSS chain was not demonstrated in this write-up. The CVE reflects the realistic worst case (DOM-XSS), because a polluted prototype can influence other components on the same page.
Consumers should therefore treat the confirmed prototype pollution as the concrete defect, and the DOM-XSS as the escalation it enables wherever a matching gadget exists in their own code.

**Suggested actions**

- Upgrade Visioweb.js to version 1.10.7 or later, where this issue has been fixed.
- If upgrading is not immediately possible, validate and sanitize any user-controlled input before it is used to set or update object properties, and avoid passing user input directly into functions that traverse or assign nested object paths (such as `getURLParameters`).
- Review any custom gadgets in your application that consume prototype-polluted values, since the impact of this vulnerability depends on what downstream code does with the polluted object.

## Timeline

{timeline from casefile — not provided in the source documents; please fill in reservation/disclosure/publication dates}

- CVE reserved: 2022-11-08
- CVE published: 2023-02-20
- CVE Full disclosure: 2026-07-30 

## More information

- CVE record: https://csirt.divd.nl/CVE-2022-3901
- CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')
- BlackFan prototype pollution payloads: https://github.com/BlackFan/client-side-prototype-pollution
- PortSwigger — Client-side prototype pollution: https://portswigger.net/web-security/prototype-pollution
