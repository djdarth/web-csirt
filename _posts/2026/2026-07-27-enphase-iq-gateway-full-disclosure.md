---
layout: post
title: Six vulnerabilities in Enphase IQ Gateway devices
author: Victor Pasman
researchers:
    - Wietse Boonstra
    - Hidde Smit
    - Max van der Horst
    - Frank Breedijk
excerpt: "Six critical vulnerabilities have been discovered in Enphase Envoy solar inverters. DIVD is assisting Enphase with locating vulnerable devices."
---
DIVD researchers Wietse Boonstra and Hidde Smit have discovered six critical vulnerabilities in Enphase IQ Gateway devices (formerly known as Enphase Envoy). The vulnerabilities are present in versions 4.x to 8.x. Version 8.2.4225 and later are patched. The first three vulnerabilities can be chained into an unauthenticated Remote Command Execution attack. On older (v7.x and earlier) devices, the password may be a weak default or calculable from the serial number, which can be read remotely (see [CVE-2020-25754](https://nvd.nist.gov/vuln/detail/CVE-2020-25754)). With these vulnerabilities, an attacker could take full control over an Enphase IQ Gateway device.

DIVD is a CVE Numbering Authority (CNA) and has used these rights to assign the following CVEs to the vulnerabilities included in the write-up below:
- {% cve CVE-2024-21876 %}
- {% cve CVE-2024-21877 %}
- {% cve CVE-2024-21878 %}
- {% cve CVE-2024-21879 %}
- {% cve CVE-2024-21880 %}
- {% cve CVE-2024-21881 %}

The rest of this post contains the full technical write-up of the vulnerabilities.

## Unauthenticated path traversal via URL parameter - CVE-2024-21876

- CVE: {% cve CVE-2024-21876 %}
- Case: {% divd DIVD-2024-00011 %}
- Discovered by: Wietse Boonstra, Hidde Smit
- Credits: Wietse Boonstra of DIVD (finder), Hidde Smit of DIVD (finder), Frank Breedijk of DIVD (analyst), Max van der Horst of DIVD (analyst)
- Products: Enphase IQ Gateway devices (formerly known as Enphase Envoy) - v8 < v8.2.4225, v7, v6, v5 and v4
- CVSS: 9.3 (CRITICAL) - `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/S:N/AU:Y/V:D/RE:H`
- Reference: Case {% divd DIVD-2024-00011 %}, {% cve CVE-2024-21876 %}
- Solution: Devices are remotely being updated by the vendor.

Enphase IQ Gateway contains a path traversal flaw in the handling of the `locale` URL parameter inside `envoy.rb`. The `get_locale` function reads the `locale` parameter and, when the page is cacheable (any request to `/home` or a path containing `/production`), the value ends up unsanitized in a cache file name that is built by `CacheUtils.cache_file` in `cache_utils.rb`:

```ruby
class CacheUtils
  CACHE_DIR = '/tmp/cache'

  def self.cache_file name
    filename = File.join( CACHE_DIR, name )
    FileUtils.mkdir_p( File.dirname( filename ) )
    filename
  end
end
```

Because the `locale` value is concatenated into the cache file name without sanitization, an unauthenticated attacker can use `../` sequences to escape `/tmp/cache` and write a file to an arbitrary path on the file system, including `/opt/emu/db/`. This is the first step of a chain with CVE-2024-21877 (insecure cache file naming) and CVE-2024-21878 (command injection via `/etc/profile`) that results in unauthenticated root command execution - see the proof of concept below.

**Suggested actions**

Do not expose your Enphase IQ Gateway device to an untrusted network (e.g. the internet or a visitor network). If internet connectivity is needed, place the device behind a NAT gateway. Update to firmware 8.2.4225 or later as soon as it is offered by Enphase.

## Authenticated insecure cache file generation based on user input - CVE-2024-21877

- CVE: {% cve CVE-2024-21877 %}
- Case: {% divd DIVD-2024-00011 %}
- Discovered by: Wietse Boonstra, Hidde Smit
- Credits: Wietse Boonstra of DIVD (finder), Hidde Smit of DIVD (finder), Frank Breedijk of DIVD (analyst), Max van der Horst of DIVD (analyst)
- Products: Enphase IQ Gateway devices (formerly known as Enphase Envoy) - v8 < v8.2.4225, v7, v6, v5 and v4
- CVSS: 8.6 (HIGH) - `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/S:N/AU:Y/V:D/RE:H`
- Reference: Case {% divd DIVD-2024-00011 %}, {% cve CVE-2024-21877 %}
- Solution: Devices are remotely being updated by the vendor.

`CacheUtils.cache_file` in `cache_utils.rb` builds the on-disk cache file name by directly joining the requested URI, the negotiated `Accept` header, and the requested locale, without validating that the resulting name stays inside `/tmp/cache`. Combined with the path traversal in CVE-2024-21876, this allows an authenticated (and, when chained with CVE-2024-21876, an unauthenticated) attacker to control both the path and the file name of a file written by the device, which is what makes it possible to plant a file inside `/opt/emu/db/` with an attacker-chosen name.

**Suggested actions**

Do not expose your Enphase IQ Gateway device to an untrusted network. Update to firmware 8.2.4225 or later as soon as it is offered by Enphase.

## Unpatched command injection via unsafe file name evaluation in /etc/profile - CVE-2024-21878

- CVE: {% cve CVE-2024-21878 %}
- Case: {% divd DIVD-2024-00011 %}
- Discovered by: Wietse Boonstra, Hidde Smit
- Credits: Wietse Boonstra of DIVD (finder), Hidde Smit of DIVD (finder), Frank Breedijk of DIVD (analyst), Max van der Horst of DIVD (analyst)
- Products: Enphase IQ Gateway devices (formerly known as Enphase Envoy) - v8.x, v7, v6, v5 and v4 (currently unpatched)
- CVSS: 7.1 (HIGH) standalone, 9.2 (CRITICAL) when chained with CVE-2024-21876 and CVE-2024-21877 - `CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/S:P/AU:Y/R:I/V:C/RE:H`
- Reference: Case {% divd DIVD-2024-00011 %}, {% cve CVE-2024-21878 %}
- Solution: No vendor patch is available for this specific behavior; exploitation is blocked once CVE-2024-21876 and CVE-2024-21877 are patched, since a file can then no longer be planted in `/opt/emu/db/`.

`/etc/profile` on the device iterates every file in `/opt/emu/db` (`$EMU_INIT_DB_DIR`) ending in `.cols` and `eval`s its content as an environment export, without validating the file name itself:

```sh
for f in $EMU_INIT_DB_DIR/*.cols; do
    [ -f $f ] || continue
    t=`basename $f .cols`
    eval export EMU_NPK_COLS_$t=`cat $f`
done
```

Because `$f` (derived from the file name) is not sanitized before being used in `eval`, a file name such as `;COMMAND;#.cols` results in arbitrary shell command execution as root the next time `/etc/profile` is sourced - on a cron job (daily at 23:00 on v7.x and earlier) or on device reboot. Chained with the path traversal (CVE-2024-21876) and insecure cache-file naming (CVE-2024-21877), an unauthenticated attacker can plant such a file and wait for execution, or force a reboot/crash to trigger it sooner.

**Suggested actions**

Do not expose your Enphase IQ Gateway device to an untrusted network. This reduces the likelihood that an attacker can reach the endpoint required to plant the malicious file in the first place.

## Authenticated command injection via unvalidated wireless configuration input - CVE-2024-21879

- CVE: {% cve CVE-2024-21879 %}
- Case: {% divd DIVD-2024-00011 %}
- Discovered by: Wietse Boonstra, Hidde Smit
- Credits: Wietse Boonstra of DIVD (finder), Hidde Smit of DIVD (finder), Frank Breedijk of DIVD (analyst), Max van der Horst of DIVD (analyst)
- Products: Enphase IQ Gateway devices (formerly known as Enphase Envoy) - v8 < v8.2.4225, v7, v6, v5 and v4
- CVSS: 8.7 (HIGH) - `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/S:P/AU:Y/R:I/V:C/RE:H`
- Reference: Case {% divd DIVD-2024-00011 %}, {% cve CVE-2024-21879 %}
- Solution: Devices are remotely being updated by the vendor.

`wireless_display.rb` sets `@wlan.regdomain` directly from the `regdomain` parameter of an authenticated POST request, without validation:

```ruby
when 'advanced_form'
  if ( @pg_parms.cm.cgi.key?('#button_apply') )
    @wlan.regdomain = @pg_parms.cm.cgi['regdomain']
  end
```

The `regdomain=` setter in `wlaninfo.rb` writes this value into `/etc/wifi/wifi.conf` and then executes `/lib/crda/setregdomain`, a shell script that sources the same config file:

```sh
[ -r "${ENVOY_WIFI_PARMFILE}" ] && . "${ENVOY_WIFI_PARMFILE}"
```

Because the config file is sourced with `.` rather than treated as data, any shell metacharacters an attacker embeds in `regdomain` are executed as root, immediately - no reboot or cron wait required.

**Suggested actions**

Do not expose your Enphase IQ Gateway device to an untrusted network. Change default credentials on older firmware. Update to firmware 8.2.4225 or later as soon as it is offered by Enphase.

## Authenticated command injection via network configuration - CVE-2024-21880

- CVE: {% cve CVE-2024-21880 %}
- Case: {% divd DIVD-2024-00011 %}
- Discovered by: Wietse Boonstra, Hidde Smit
- Credits: Wietse Boonstra of DIVD (finder), Hidde Smit of DIVD (finder), Frank Breedijk of DIVD (analyst), Max van der Horst of DIVD (analyst)
- Products: Enphase IQ Gateway devices (formerly known as Enphase Envoy) - v7, v6, v5 and v4
- CVSS: 8.6 (HIGH) - `CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/S:P/AU:Y/R:I/V:C/RE:H`
- Reference: Case {% divd DIVD-2024-00011 %}, {% cve CVE-2024-21880 %}
- Solution: Devices are remotely being updated by the vendor.

Devices with firmware prior to 7.0 do not validate the `default_apn` parameter submitted to the `/admin/lib/network_display.json` endpoint. On these older firmware versions, the default installer credentials are `envoy:nnnnnn`, where `nnnnnn` is the last six digits of the device's serial number, which can be read remotely and unauthenticated from `/info.xml`. Combined, this allows an authenticated attacker - including one who only guessed the predictable default password - to inject and execute arbitrary shell commands as root by manipulating `default_apn` and then triggering a network adapter restart.

**Suggested actions**

Do not expose your Enphase IQ Gateway device to an untrusted network. Change default credentials. Restrict network access to the administrative interface to trusted users. Update to firmware 8.2.4225 or later as soon as it is offered by Enphase.

## Authenticated command execution via malicious encrypted package upload - CVE-2024-21881

- CVE: {% cve CVE-2024-21881 %}
- Case: {% divd DIVD-2024-00011 %}
- Discovered by: Wietse Boonstra, Hidde Smit
- Credits: Wietse Boonstra of DIVD (finder), Hidde Smit of DIVD (finder), Frank Breedijk of DIVD (analyst), Max van der Horst of DIVD (analyst)
- Products: Enphase IQ Gateway devices (formerly known as Enphase Envoy) - v5 and v4
- CVSS: 8.6 (HIGH) - `CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/S:P/AU:Y/R:I/V:C/RE:H`
- Reference: Case {% divd DIVD-2024-00011 %}, {% cve CVE-2024-21881 %}
- Solution: Devices are remotely being updated by the vendor.

`/opt/emu/httpd/rhtdocs/installer/agf/upload_profile_package.rb` decrypts an uploaded `.eepkg` package and, if it contains a migration script, executes it with `system()`:

```ruby
if (handle_file_upload(UPLOAD_PATH, UPLOAD_FILE))
  if (system("md5sum #{UPLOAD_PATH}/#{UPLOAD_FILE} > #{UPLOAD_PATH}/#{UPLOAD_FILE}.md5sum; eecrypt --action decrypt --input #{UPLOAD_PATH}/#{UPLOAD_FILE} --output stdout | gunzip > #{UPLOAD_PATH}/#{DECRYPTED_FILE}"))
    # -----
    if (File.exist?("#{UPLOAD_PATH}/#{MIGRATION_SCRIPT}"))
      system("ruby #{UPLOAD_PATH}/#{MIGRATION_SCRIPT} verbose &")
    end
end
```

Because the encryption used for `.eepkg` packages relies on a key and tooling (`eecrypt`) that is not adequately protected, an authenticated installer-level attacker can craft their own valid encrypted package containing an arbitrary `migration_script`, upload it, and have the device execute it as root.

**Suggested actions**

Do not expose your Enphase IQ Gateway device to an untrusted network. Update to firmware 8.2.4225 or later as soon as it is offered by Enphase, or where a full update is not possible for these older device generations, restrict installer-level access as tightly as possible.

## Timeline

- **2024-04-11**: Wietse Boonstra and Hidde Smit report six vulnerabilities to DIVD CSIRT.
- **2024-04-17**: Vendor notified via email to cybersecurity@enphaseenergy.com and cybersecurity@enphase.com and via ticket 16059299.
- **2024-04-18**: Vendor acknowledges receipt of the vulnerability (time to acknowledge: 1 day).
- **2024-04-18**: 1st meeting between DIVD researchers and vendor.
- **2024-04-18 to 2024-07-12**: DIVD and Enphase work together (time to patch: ~3 months).
- **2024-07-12**: Enphase reports that the vulnerabilities are patched. Finders validate the fixes. Enphase starts updating devices.
- **2024-07-12**: DIVD starts scanning for vulnerable Envoy devices to assist with prioritizing the patch process.
- **2024-04-18 to 2024-08-10**: Time to limited disclosure.
- **2024-08-10**: Limited disclosure of CVEs by Enphase.
- **2024-08-10**: Limited disclosure of CVEs by DIVD following Enphase disclosure.
- **2026-07-27**: Full disclosure of CVEs by DIVD.

## More information

* [Enphase Advisories](https://enphase.com/cybersecurity/advisories/ensa-2024-1)
* {% cve CVE-2024-21876 %} - [Enphase Advisory for CVE-2024-21876](https://enphase.com/cybersecurity/advisories/ensa-2024-1)
* {% cve CVE-2024-21877 %} - [Enphase Advisory for CVE-2024-21877](https://enphase.com/cybersecurity/advisories/ensa-2024-2)
* {% cve CVE-2024-21878 %} - [Enphase Advisory for CVE-2024-21878](https://enphase.com/cybersecurity/advisories/ensa-2024-3)
* {% cve CVE-2024-21879 %} - [Enphase Advisory for CVE-2024-21879](https://enphase.com/cybersecurity/advisories/ensa-2024-4)
* {% cve CVE-2024-21880 %} - [Enphase Advisory for CVE-2024-21880](https://enphase.com/cybersecurity/advisories/ensa-2024-5)
* {% cve CVE-2024-21881 %} - [Enphase Advisory for CVE-2024-21881](https://enphase.com/cybersecurity/advisories/ensa-2024-6)
* {% divd DIVD-2024-00011 %} - full case file
* Recommendation: Do not expose your Enphase equipment to untrusted networks (e.g. the internet or a visitor network). If internet connectivity is needed, place the device behind a NAT gateway.
