---
layout: post
title: Cloudflow
author: Victor Pasman
researchers:
    - Witold Gorecki
excerpt: "Multiple vulnerabilities in the Hybrid Software Cloudflow CLOUDFLOW PROOFSCOPE module, including unauthenticated local file inclusion and unauthenticated file upload."
---
Multiple vulnerabilities were identified within the Hybrid Software Cloudflow CLOUDFLOW PROOFSCOPE module during an external penetration test from a black-box perspective. The issues allow an unauthenticated attacker with network access to the application to retrieve arbitrary files from the underlying server's local filesystem, to list and download files stored in the application's built-in storage, and to upload files to that storage without authentication.

DIVD is a CVE Numbering Authority (CNA) and has used these rights to assign the following CVEs to the vulnerabilities included in the write-up below:
- {% cve CVE-2022-41216 %}
- {% cve CVE-2022-41217 %}

The rest of this post contains the full technical write-up of the vulnerabilities.

## Unauthenticated Local File Inclusion - CVE-2022-41216

- CVE: {% cve CVE-2022-41216 %}
- Case: {% divd DIVD-2022-00052 %}
- Discovered by: Witold Gorecki
- Credits: Witold Gorecki (witold@gorecki.org, researcher), Victor Pasman (Analyst DIVD)
- Products: Cloudflow from Hybrid Software (CLOUDFLOW PROOFSCOPE module), versions &le; 2.3.1
- CVSS: 9.4 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H) — CWE-829: Inclusion of Functionality from Untrusted Control Sphere / CAPEC-252: PHP Local File Inclusion
- Reference: Case {% divd DIVD-2022-00052 %}, {% cve CVE-2022-41216 %}
- Solution: Upgrade to version 2.3.2 of Cloudflow

### Description

Within the internet-facing instance of CLOUDFLOW PROOFSCOPE it was found that one of the URLs contains a `url` parameter that is used for accessing files from the web application's built-in storage via the `cloudflow://` protocol scheme:

```
GET /portal.cgi?asset=download_file&url=cloudflow://path_to_file
```

It was found that the `file://` protocol scheme could be used instead to obtain files directly from the web server's local filesystem, without any authentication:

```
GET /portal.cgi?asset=download_file&url=file:///C:/windows/system32/drivers/etc/hosts
```

It was additionally observed that the web server process was running with administrative privileges, since files from the local administrator's home directory (normally accessible only to an administrative user) could be retrieved, including:

- `C:\Users\Administrator\NTUser.dat`
- `C:\Users\Administrator\appdata\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

It could not be confirmed, due to limited access during testing, whether running the web server with administrative privileges was a misconfiguration by the server administrator or a default setting of the CLOUDFLOW PROOFSCOPE software.

### Risk

A potential attacker could obtain files from the server's local filesystem and steal or leak confidential information. Because the web application runs with administrator-level privileges, this could include sensitive files such as `NTUser.dat` or PowerShell command history, both of which may contain sensitive information.

### Proof of Concept

- Requesting `file:///C:/windows/system32/drivers/etc/hosts` returned the contents of the server's hosts file with an HTTP 200 OK response.
- Requesting the PowerShell `ConsoleHost_history.txt` file from the local administrator's profile also returned file contents, confirming the web server process runs with administrative privileges.

**Suggested actions**

- Remove support for the `file://` protocol scheme and deny any requests to the `url` parameter that contain this scheme without further processing.
- Review whether the web server process requires administrative privileges and, if possible, reduce it to the least privilege required.
- Upgrade to Cloudflow version 2.3.2 or later.

## Unauthenticated File Upload - CVE-2022-41217

- CVE: {% cve CVE-2022-41217 %}
- Case: {% divd DIVD-2022-00052 %}
- Discovered by: Witold Gorecki
- Credits: Witold Gorecki (witold@gorecki.org, researcher), Victor Pasman (Analyst DIVD)
- Products: Cloudflow from Hybrid Software (CLOUDFLOW PROOFSCOPE module), versions &le; 2.3.1
- CVSS: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) — CWE-434: Unrestricted Upload of File with Dangerous Type / CAPEC-650: Upload a Web Shell to a Web Server
- Reference: Case {% divd DIVD-2022-00052 %}, {% cve CVE-2022-41217 %}
- Solution: Upgrade to version 2.3.2 of Cloudflow

### Description

Within the internet-facing instance of CLOUDFLOW PROOFSCOPE it was found that one of the URLs allows uploading files to the web application's built-in storage without any authentication:

```
POST /portal.cgi?hub=upload_file&whitepaper_name=<REDACTED>&input_name=<REDACTED>
```

The uploaded file could subsequently be downloaded again via the built-in `cloudflow://` file retrieval endpoint:

```
GET /portal.cgi?asset=download_file&url=cloudflow://<path>/test123.txt
```

A related finding from the same assessment, not separately assigned a CVE identifier in the source material provided, is that one of the application's URLs (`POST /portal.cgi/asset/list`) also allows listing files stored in the built-in storage without authentication, and that listed files can subsequently be downloaded via the same `cloudflow://` retrieval endpoint. This information-disclosure issue was rated Medium (CVSS 5.3, CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) in the original assessment and is closely related to the file storage exposed by this upload vulnerability.

### Risk

A potential attacker could upload malicious files to the CLOUDFLOW PROOFSCOPE built-in storage and use them for malicious purposes, such as phishing campaigns. Depending on the underlying storage solution, uploading a large number of large files could also generate significant costs (cloud storage) or cause a Denial of Service condition (local filesystem storage). Combined with the unauthenticated file-listing/download issue described above, an attacker could also enumerate and retrieve files already stored by legitimate users.

### Proof of Concept

- A file (`test123.txt`) was uploaded via `POST /portal.cgi?hub=upload_file` with no authentication required, returning a `cloudflow://` path to the stored file.
- The uploaded file was then retrieved via `GET /portal.cgi?asset=download_file&url=cloudflow://.../test123.txt`, confirming the round trip.
- File listing via `POST /portal.cgi/asset/list` returned metadata (id, URL, filename, path, file type, timestamps) for existing files in storage without authentication.

**Suggested actions**

- Restrict file upload functionality to authenticated users only.
- If unauthenticated uploads are required by design, implement:
  - File size limits;
  - Restrictions on the number of files that can be uploaded (e.g. per IP, User-Agent, and screen size combination);
  - A CAPTCHA mechanism to prevent automated abuse.
- Restrict file listing and download functionality to authenticated users only.
- Upgrade to Cloudflow version 2.3.2 or later.

## Timeline

- **2023-02-21**: DIVD released CVE-2022-41216 and CVE-2022-41217.
- **2024-07-21**: Case closed due to inactivity.
- **2026-07-27**: Full disclosure of CVE's.

## More information

* {% cve CVE-2022-41216 %}
* {% cve CVE-2022-41217 %}
* {% divd DIVD-2022-00052 %}
