<!-- Contrast VEX Advisor Report -->

# Contrast VEX Advisor
## Review of Automatically-Generated VEX Claims

---

**Report Date:** September 2, 2026
**Assessment Type:** VEX Claim Soundness Review

---

## Summary

This report reviews VEX (Vulnerability Exploitability eXchange) claims generated from Contrast Security runtime library-usage and CVE Shield/Protect data. It does not re-derive whether a CVE exists - it judges whether each `not_affected`/`in_triage` claim is well-supported enough to rely on as-is, or whether a human should look at it first.

**Coverage:** 1 application(s), 235 VEX statement(s) reviewed.

**Key Findings:**

- **61 of 235 claim(s) flagged for human review** before relying on them.
- **8 flagged claim(s) are on CVEs in the CISA Known Exploited Vulnerabilities (KEV) catalog** - actively exploited in the wild: CVE-2022-22965, CVE-2018-1273, CVE-2025-24813, CVE-2020-1938, CVE-2017-12617, CVE-2023-44487.
- **10 flagged claim(s) have an EPSS score ≥ 0.5** (50%+ predicted exploitation likelihood): CVE-2017-17485, CVE-2024-38819, CVE-2019-0232, CVE-2019-0199, CVE-2025-55752, CVE-2019-10072 (+4 more).
- Application(s) rated CRITICAL/HIGH risk: SAML-PetClinic-Demo.

### Applications

| Application | Risk Level | Statements |
|-------------|------------|------------|
| SAML-PetClinic-Demo | HIGH | 235 |

| Risk Level | Applications |
|------------|--------------|
| HIGH | 1 |

---

## Application Detail

### SAML-PetClinic-Demo

**Risk Level:** HIGH

SAML-PetClinic-Demo carries roughly 210 VEX claims across ~40 outdated libraries (jackson-databind 2.8.8, tomcat-embed-core 8.5.15, spring-web/webmvc/beans 4.3.9, snakeyaml 1.17, netty 3.5.7, plexus-utils 3.0.8, etc.), almost all `not_affected`. A meaningful minority are backed by `code_not_reachable` (zero classes loaded) and are structurally sound; the majority instead rely on 288 days of non-execution as the sole justification, and a large number of those cover critical/high-severity or KEV-listed CVEs.

**Risk Rationale:** The 288-day observation window comfortably clears the 30-day policy threshold, so duration alone isn't the problem. The problem is scale and severity: dozens of critical-severity jackson-databind CVEs, four instances of the KEV-listed Spring4Shell CVE-2022-22965 (three of which rely on duration-only reasoning rather than code_not_reachable), KEV-listed Tomcat Ghostcat/CVE-2020-1938, CVE-2017-12617, CVE-2025-24813, and CVE-2023-44487, plus KEV-listed spring-data-commons CVE-2018-1273 (EPSS 0.97) are all accepted purely on 'no observed execution' rather than structural non-reachability. Given the number and severity of these, this VEX set should not be trusted at face value for its critical/KEV entries.

**Recommendation:** Prioritize human review of: all four spring-beans/spring-webmvc/spring-web instances tied to CVE-2022-22965 (data-binding RCE, KEV), spring-data-commons CVE-2018-1273 (KEV, EPSS 0.97), the KEV-listed tomcat-embed-core CVEs (CVE-2025-24813, CVE-2020-1938, CVE-2017-12617, CVE-2023-44487), and the ~24 critical-severity jackson-databind CVEs on 2.8.8. For these, verify with a manual reachability/pen-test check or accept the library upgrade instead of the VEX claim. The `code_not_reachable` claims (htmlunit, snakeyaml, netty, plexus-utils, jetty-http, bootstrap, junit, commons-lang/-lang3, commons-compress, neko-htmlunit, commons-io, httpclient, spring-boot-starter-web/-actuator) can be relied on as-is.

#### Needs Review (61)

| CVE | Library | Severity | State | Rationale |
|-----|---------|----------|-------|-----------|
| CVE-2018-14721 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (10.0) accepted solely on 288 days of non-execution with no structural non-reachability; jackson-databind deserialization CVEs of this class are historically found reachable unexpectedly. |
| CVE-2018-11307 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8) accepted on duration alone; no code_not_reachable backing. |
| CVE-2017-17485 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8) with elevated EPSS (0.5, 98.8th pct) accepted purely on non-execution duration; warrants a closer look. |
| CVE-2020-8840 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8), EPSS 0.27, duration-only justification - worth a manual check. |
| CVE-2019-16335 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8) accepted solely on non-execution duration. |
| CVE-2019-20330 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8) accepted solely on non-execution duration. |
| CVE-2018-14718 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8) accepted solely on non-execution duration. |
| CVE-2018-14720 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8) accepted solely on non-execution duration. |
| CVE-2018-14719 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8) accepted solely on non-execution duration. |
| CVE-2020-9548 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8) accepted solely on non-execution duration. |
| CVE-2019-14540 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8) accepted solely on non-execution duration. |
| CVE-2020-9547 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8) accepted solely on non-execution duration. |
| CVE-2019-14892 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8) accepted solely on non-execution duration. |
| CVE-2019-16942 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8) accepted solely on non-execution duration. |
| CVE-2018-19361 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8) accepted solely on non-execution duration. |
| CVE-2019-16943 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8) accepted solely on non-execution duration. |
| CVE-2018-19360 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8) accepted solely on non-execution duration. |
| CVE-2018-19362 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8) accepted solely on non-execution duration. |
| CVE-2019-17267 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8) accepted solely on non-execution duration. |
| CVE-2017-7525 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8), EPSS 0.38, duration-only - the well-known jackson polymorphic-deserialization gadget class, worth verifying. |
| CVE-2018-7489 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8), EPSS 0.2, accepted solely on non-execution duration. |
| CVE-2019-17531 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8) accepted solely on non-execution duration. |
| CVE-2017-15095 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8) accepted solely on non-execution duration. |
| CVE-2019-14379 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | Critical (9.8) accepted solely on non-execution duration. |
| CVE-2020-36179 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | High severity with EPSS 0.21 (97th pct) accepted on duration alone; worth a closer look. |
| CVE-2020-25649 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | High severity with EPSS 0.18 (97th pct) accepted purely on duration; worth verifying. |
| CVE-2019-12086 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | High severity with EPSS 0.22 (97th pct) accepted purely on non-execution duration; worth verifying. |
| CVE-2020-10683 | `pkg:maven/dom4j/dom4j@1.6.1` | critical | not_affected | Critical (9.8) dom4j XXE, only 1 of 190 classes ever used, but that one class is loaded and the claim relies purely on non-execution duration - worth confirming that class isn't the vulnerable entry point. |
| CVE-2022-22965 | `pkg:maven/org.springframework.boot/spring-boot-starter-web@1.5.4.RELEASE` | critical | not_affected | KEV-listed Spring4Shell (EPSS 1.0) on spring-beans - library IS loaded (202/408 classes) and accepted purely on non-execution duration. High priority for manual review. |
| CVE-2018-1273 | `pkg:maven/org.springframework.data/spring-data-commons@1.13.4.RELEASE` | critical | not_affected | KEV-listed, critical (9.8), EPSS 0.97 (99.9th pct) - one of the most exploitable CVEs in this VEX set, yet accepted purely on non-execution duration. Requires explicit human verification, not automated acceptance. |
| CVE-2022-41853 | `pkg:maven/org.hsqldb/hsqldb@2.3.5` | critical | not_affected | Critical (9.8) accepted solely on non-execution duration despite substantial hsqldb usage (229/601 classes) - worth confirming. |
| CVE-2017-5929 | `pkg:maven/ch.qos.logback/logback-core@1.1.11` | critical | not_affected | Critical (9.8) on logback-classic, same underlying gap as the logback-core instance: accepted purely on non-execution duration. |
| CVE-2016-1000027 | `pkg:maven/org.springframework/spring-web@4.3.9.RELEASE` | critical | not_affected | Critical (9.8) spring-web deserialization CVE accepted solely on non-execution duration despite meaningful library usage (211/559 classes); worth verifying. |
| CVE-2022-22965 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | critical | not_affected | KEV-listed Spring4Shell (EPSS 1.0) on spring-beans - library IS loaded (202/408 classes) and accepted purely on non-execution duration. High priority for manual review. |
| CVE-2024-38819 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | high | not_affected | High severity with elevated EPSS (0.55, 99th pct) accepted purely on non-execution duration; worth verifying. |
| CVE-2017-5929 | `pkg:maven/ch.qos.logback/logback-classic@1.1.11` | critical | not_affected | Critical (9.8) on logback-classic, same underlying gap as the logback-core instance: accepted purely on non-execution duration. |
| CVE-2022-22965 | `pkg:maven/org.springframework/spring-beans@4.3.9.RELEASE` | critical | not_affected | KEV-listed Spring4Shell (EPSS 1.0) on spring-beans - library IS loaded (202/408 classes) and accepted purely on non-execution duration. High priority for manual review. |
| CVE-2018-8014 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | critical | not_affected | Critical (9.8) on heavily-used tomcat-embed-core (387/1481 classes), accepted purely on non-execution duration. |
| CVE-2025-24813 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | critical | not_affected | KEV-listed, critical (9.8), EPSS 1.0 - among the most exploitable CVEs in this set, accepted purely on duration; requires human verification. |
| CVE-2026-43512 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | critical | not_affected | Critical (9.8) accepted purely on non-execution duration on a heavily-loaded library. |
| CVE-2020-1938 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | critical | not_affected | KEV-listed (Ghostcat), critical (9.8), EPSS 0.99 - requires human verification rather than duration-only acceptance. |
| CVE-2025-31651 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | critical | not_affected | Critical (9.8) accepted purely on non-execution duration. |
| CVE-2024-50379 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | critical | not_affected | Critical (9.8), EPSS 0.44, accepted purely on non-execution duration. |
| CVE-2026-43515 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | critical | not_affected | Critical (9.1) accepted purely on non-execution duration. |
| CVE-2019-0232 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | High severity with EPSS 1.0 (near-certain exploitation observed elsewhere) accepted purely on non-execution duration. |
| CVE-2017-12617 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | KEV-listed, EPSS 1.0 - requires human verification rather than duration-only acceptance. |
| CVE-2019-0199 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | High severity, EPSS 0.73, accepted purely on non-execution duration. |
| CVE-2018-8034 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | High severity, EPSS 0.21, accepted purely on non-execution duration. |
| CVE-2025-55752 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | High severity, EPSS 0.67, accepted purely on non-execution duration. |
| CVE-2019-10072 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | High severity, EPSS 0.73, accepted purely on non-execution duration. |
| CVE-2021-25122 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | High severity, EPSS 0.18, accepted purely on non-execution duration. |
| CVE-2025-48988 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | High severity, EPSS 0.57, accepted purely on non-execution duration. |
| CVE-2025-31650 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | High severity, EPSS 0.6, accepted purely on non-execution duration. |
| CVE-2024-24549 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | High severity, EPSS 0.23, accepted purely on non-execution duration. |
| CVE-2023-44487 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | KEV-listed (HTTP/2 Rapid Reset), EPSS 1.0 - requires human verification rather than duration-only acceptance. |
| CVE-2018-1336 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | High severity, EPSS 0.21, accepted purely on non-execution duration. |
| CVE-2020-9484 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | High severity, EPSS 0.57, accepted purely on non-execution duration. |
| CVE-2026-41901 | `pkg:maven/org.thymeleaf/thymeleaf@3.0.6.RELEASE` | critical | not_affected | Critical (9.0) thymeleaf CVE accepted solely on non-execution duration despite substantial library usage (367/549 classes); worth verifying. |
| CVE-2026-40477 | `pkg:maven/org.thymeleaf/thymeleaf@3.0.6.RELEASE` | critical | not_affected | Critical (9.0) accepted solely on non-execution duration. |
| CVE-2026-40478 | `pkg:maven/org.thymeleaf/thymeleaf@3.0.6.RELEASE` | critical | not_affected | Critical (9.0) accepted solely on non-execution duration. |
| CVE-2022-34169 | `pkg:maven/xalan/xalan@2.7.2` | high | not_affected | High severity with very high EPSS (0.81, 99.6th pct) accepted purely on non-execution duration despite the library being loaded (7/1501 classes) - worth verifying given the strong exploitability signal. |

#### Sound (174)

<details><summary>174 claim(s) assessed as sound as-is - expand for the full list</summary>

| CVE | Library | Severity | State |
|-----|---------|----------|-------|
| CVE-2020-10673 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2020-35728 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2020-35491 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2020-35490 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2020-36184 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2020-36182 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2020-36180 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2020-36186 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2020-36181 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2020-10650 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2020-36185 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2020-36188 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2020-36187 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2020-36189 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2020-36183 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2021-20190 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2018-5968 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2020-24616 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2020-24750 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2022-42004 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2022-42003 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2018-12023 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2020-36518 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2019-14439 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2018-12022 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected |
| CVE-2019-12384 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | medium | not_affected |
| CVE-2019-12814 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | medium | not_affected |
| CVE-2023-26119 | `pkg:maven/net.sourceforge.htmlunit/htmlunit@2.21` | critical | not_affected |
| CVE-2020-5529 | `pkg:maven/net.sourceforge.htmlunit/htmlunit@2.21` | high | not_affected |
| CVE-2018-1000632 | `pkg:maven/dom4j/dom4j@1.6.1` | high | not_affected |
| CVE-2022-1471 | `pkg:maven/org.yaml/snakeyaml@1.17` | critical | not_affected |
| CVE-2022-25857 | `pkg:maven/org.yaml/snakeyaml@1.17` | high | not_affected |
| CVE-2017-18640 | `pkg:maven/org.yaml/snakeyaml@1.17` | high | not_affected |
| CVE-2022-38749 | `pkg:maven/org.yaml/snakeyaml@1.17` | medium | not_affected |
| CVE-2022-41854 | `pkg:maven/org.yaml/snakeyaml@1.17` | medium | not_affected |
| CVE-2022-38751 | `pkg:maven/org.yaml/snakeyaml@1.17` | medium | not_affected |
| CVE-2022-38752 | `pkg:maven/org.yaml/snakeyaml@1.17` | medium | not_affected |
| CVE-2022-38750 | `pkg:maven/org.yaml/snakeyaml@1.17` | medium | not_affected |
| CVE-2018-1274 | `pkg:maven/org.springframework.data/spring-data-commons@1.13.4.RELEASE` | high | not_affected |
| CVE-2026-41716 | `pkg:maven/org.springframework.data/spring-data-commons@1.13.4.RELEASE` | high | not_affected |
| CVE-2026-41721 | `pkg:maven/org.springframework.data/spring-data-commons@1.13.4.RELEASE` | medium | not_affected |
| CVE-2026-41711 | `pkg:maven/org.springframework.data/spring-data-commons@1.13.4.RELEASE` | medium | not_affected |
| CVE-2018-1259 | `pkg:maven/org.springframework.data/spring-data-commons@1.13.4.RELEASE` | unknown | not_affected |
| CVE-2023-6378 | `pkg:maven/ch.qos.logback/logback-core@1.1.11` | high | not_affected |
| CVE-2021-42550 | `pkg:maven/ch.qos.logback/logback-core@1.1.11` | medium | not_affected |
| CVE-2026-10532 | `pkg:maven/ch.qos.logback/logback-core@1.1.11` | unknown | not_affected |
| CVE-2026-1225 | `pkg:maven/ch.qos.logback/logback-core@1.1.11` | unknown | not_affected |
| CVE-2026-9828 | `pkg:maven/ch.qos.logback/logback-core@1.1.11` | unknown | not_affected |
| CVE-2025-11226 | `pkg:maven/ch.qos.logback/logback-core@1.1.11` | unknown | not_affected |
| CVE-2024-12798 | `pkg:maven/ch.qos.logback/logback-core@1.1.11` | unknown | not_affected |
| CVE-2024-12801 | `pkg:maven/ch.qos.logback/logback-core@1.1.11` | unknown | not_affected |
| CVE-2024-22243 | `pkg:maven/org.springframework/spring-web@4.3.9.RELEASE` | high | not_affected |
| CVE-2024-22262 | `pkg:maven/org.springframework/spring-web@4.3.9.RELEASE` | high | not_affected |
| CVE-2024-22259 | `pkg:maven/org.springframework/spring-web@4.3.9.RELEASE` | high | not_affected |
| CVE-2018-11039 | `pkg:maven/org.springframework/spring-web@4.3.9.RELEASE` | medium | not_affected |
| CVE-2024-38820 | `pkg:maven/org.springframework/spring-web@4.3.9.RELEASE` | medium | not_affected |
| CVE-2024-38809 | `pkg:maven/org.springframework/spring-web@4.3.9.RELEASE` | medium | not_affected |
| CVE-2026-41842 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | high | not_affected |
| CVE-2026-41845 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | medium | not_affected |
| CVE-2026-41846 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | medium | not_affected |
| CVE-2026-41844 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | medium | not_affected |
| CVE-2026-41841 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | medium | not_affected |
| CVE-2026-41843 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | medium | not_affected |
| CVE-2026-22745 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | medium | not_affected |
| CVE-2026-41853 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | medium | not_affected |
| CVE-2026-22741 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | low | not_affected |
| CVE-2023-6378 | `pkg:maven/ch.qos.logback/logback-classic@1.1.11` | high | not_affected |
| CVE-2022-22970 | `pkg:maven/org.springframework/spring-beans@4.3.9.RELEASE` | medium | not_affected |
| CVE-2019-17563 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected |
| CVE-2023-46589 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected |
| CVE-2026-41284 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected |
| CVE-2026-43513 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected |
| CVE-2024-34750 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected |
| CVE-2025-49125 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected |
| CVE-2025-52434 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected |
| CVE-2022-42252 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected |
| CVE-2025-53506 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected |
| CVE-2025-52520 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected |
| CVE-2025-46701 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected |
| CVE-2019-12418 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected |
| CVE-2021-25329 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected |
| CVE-2018-1305 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | medium | not_affected |
| CVE-2019-0221 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | medium | not_affected |
| CVE-2021-24122 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | medium | not_affected |
| CVE-2018-8037 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | medium | not_affected |
| CVE-2018-1304 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | medium | not_affected |
| CVE-2025-61795 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | medium | not_affected |
| CVE-2024-21733 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | medium | not_affected |
| CVE-2023-42795 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | medium | not_affected |
| CVE-2018-11784 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | medium | not_affected |
| CVE-2017-1000487 | `pkg:maven/org.codehaus.plexus/plexus-utils@3.0.8` | critical | not_affected |
| CVE-2025-67030 | `pkg:maven/org.codehaus.plexus/plexus-utils@3.0.8` | high | not_affected |
| CVE-2022-4244 | `pkg:maven/org.codehaus.plexus/plexus-utils@3.0.8` | high | not_affected |
| CVE-2022-4245 | `pkg:maven/org.codehaus.plexus/plexus-utils@3.0.8` | medium | not_affected |
| CVE-2019-20445 | `pkg:maven/io.netty/netty@3.5.7.Final` | critical | not_affected |
| CVE-2019-20444 | `pkg:maven/io.netty/netty@3.5.7.Final` | critical | not_affected |
| CVE-2021-37136 | `pkg:maven/io.netty/netty@3.5.7.Final` | high | not_affected |
| CVE-2021-37137 | `pkg:maven/io.netty/netty@3.5.7.Final` | high | not_affected |
| CVE-2019-16869 | `pkg:maven/io.netty/netty@3.5.7.Final` | high | not_affected |
| CVE-2021-43797 | `pkg:maven/io.netty/netty@3.5.7.Final` | medium | not_affected |
| CVE-2021-21409 | `pkg:maven/io.netty/netty@3.5.7.Final` | medium | not_affected |
| CVE-2021-21295 | `pkg:maven/io.netty/netty@3.5.7.Final` | medium | not_affected |
| CVE-2021-21290 | `pkg:maven/io.netty/netty@3.5.7.Final` | medium | not_affected |
| CVE-2015-2156 | `pkg:maven/io.netty/netty@3.5.7.Final` | unknown | not_affected |
| CVE-2026-2332 | `pkg:maven/org.eclipse.jetty/jetty-http@9.4.5.v20170502` | critical | not_affected |
| CVE-2025-11143 | `pkg:maven/org.eclipse.jetty/jetty-http@9.4.5.v20170502` | medium | not_affected |
| CVE-2024-6763 | `pkg:maven/org.eclipse.jetty/jetty-http@9.4.5.v20170502` | medium | not_affected |
| CVE-2023-40167 | `pkg:maven/org.eclipse.jetty/jetty-http@9.4.5.v20170502` | medium | not_affected |
| CVE-2022-2047 | `pkg:maven/org.eclipse.jetty/jetty-http@9.4.5.v20170502` | low | not_affected |
| CVE-2018-3258 | `pkg:maven/mysql/mysql-connector-java@5.1.42` | high | not_affected |
| CVE-2023-22102 | `pkg:maven/mysql/mysql-connector-java@5.1.42` | high | not_affected |
| CVE-2019-2692 | `pkg:maven/mysql/mysql-connector-java@5.1.42` | medium | not_affected |
| CVE-2022-21363 | `pkg:maven/mysql/mysql-connector-java@5.1.42` | unknown | not_affected |
| CVE-2026-22733 | `pkg:maven/org.springframework.boot/spring-boot-starter-actuator@1.5.4.RELEASE` | high | not_affected |
| CVE-2022-27772 | `pkg:maven/org.springframework.boot/spring-boot@1.5.4.RELEASE` | high | not_affected |
| CVE-2025-22235 | `pkg:maven/org.springframework.boot/spring-boot@1.5.4.RELEASE` | high | not_affected |
| CVE-2026-40973 | `pkg:maven/org.springframework.boot/spring-boot@1.5.4.RELEASE` | high | not_affected |
| CVE-2018-1196 | `pkg:maven/org.springframework.boot/spring-boot@1.5.4.RELEASE` | medium | not_affected |
| CVE-2022-28366 | `pkg:maven/net.sourceforge.htmlunit/neko-htmlunit@2.21` | high | not_affected |
| CVE-2022-29546 | `pkg:maven/net.sourceforge.htmlunit/neko-htmlunit@2.21` | high | not_affected |
| CVE-2022-25647 | `pkg:maven/com.google.code.gson/gson@2.8.0` | high | not_affected |
| CVE-2021-36090 | `pkg:maven/org.apache.commons/commons-compress@1.9` | high | not_affected |
| CVE-2021-35516 | `pkg:maven/org.apache.commons/commons-compress@1.9` | high | not_affected |
| CVE-2021-35517 | `pkg:maven/org.apache.commons/commons-compress@1.9` | high | not_affected |
| CVE-2021-35515 | `pkg:maven/org.apache.commons/commons-compress@1.9` | high | not_affected |
| CVE-2024-25710 | `pkg:maven/org.apache.commons/commons-compress@1.9` | medium | not_affected |
| CVE-2018-11771 | `pkg:maven/org.apache.commons/commons-compress@1.9` | medium | not_affected |
| CVE-2018-1272 | `pkg:maven/org.springframework/spring-core@4.3.9.RELEASE` | high | not_affected |
| CVE-2018-15756 | `pkg:maven/org.springframework/spring-core@4.3.9.RELEASE` | high | not_affected |
| CVE-2026-41848 | `pkg:maven/org.springframework/spring-core@4.3.9.RELEASE` | high | not_affected |
| CVE-2018-11040 | `pkg:maven/org.springframework/spring-core@4.3.9.RELEASE` | high | not_affected |
| CVE-2018-1257 | `pkg:maven/org.springframework/spring-core@4.3.9.RELEASE` | medium | not_affected |
| CVE-2018-1271 | `pkg:maven/org.springframework/spring-core@4.3.9.RELEASE` | medium | not_affected |
| CVE-2018-1199 | `pkg:maven/org.springframework/spring-core@4.3.9.RELEASE` | medium | not_affected |
| CVE-2021-22096 | `pkg:maven/org.springframework/spring-core@4.3.9.RELEASE` | medium | not_affected |
| CVE-2026-41850 | `pkg:maven/org.springframework/spring-expression@4.3.9.RELEASE` | high | not_affected |
| CVE-2026-41851 | `pkg:maven/org.springframework/spring-expression@4.3.9.RELEASE` | high | not_affected |
| CVE-2026-41849 | `pkg:maven/org.springframework/spring-expression@4.3.9.RELEASE` | high | not_affected |
| CVE-2023-20863 | `pkg:maven/org.springframework/spring-expression@4.3.9.RELEASE` | medium | not_affected |
| CVE-2023-20861 | `pkg:maven/org.springframework/spring-expression@4.3.9.RELEASE` | medium | not_affected |
| CVE-2022-22950 | `pkg:maven/org.springframework/spring-expression@4.3.9.RELEASE` | medium | not_affected |
| CVE-2026-41852 | `pkg:maven/org.springframework/spring-expression@4.3.9.RELEASE` | medium | not_affected |
| CVE-2024-38808 | `pkg:maven/org.springframework/spring-expression@4.3.9.RELEASE` | medium | not_affected |
| CVE-2023-20883 | `pkg:maven/org.springframework.boot/spring-boot-autoconfigure@1.5.4.RELEASE` | high | not_affected |
| CVE-2024-23672 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-websocket@8.5.15` | medium | not_affected |
| CVE-2020-25638 | `pkg:maven/org.hibernate/hibernate-core@5.0.4.Final` | high | not_affected |
| CVE-2019-14900 | `pkg:maven/org.hibernate/hibernate-core@5.0.4.Final` | medium | not_affected |
| CVE-2017-7536 | `pkg:maven/org.hibernate/hibernate-validator@5.3.5.Final` | high | not_affected |
| CVE-2023-2976 | `pkg:maven/com.google.guava/guava@19.0` | high | not_affected |
| CVE-2020-8908 | `pkg:maven/com.google.guava/guava@19.0` | low | not_affected |
| CVE-2012-0881 | `pkg:maven/xerces/xercesimpl@2.11.0` | unknown | not_affected |
| CVE-2013-4002 | `pkg:maven/xerces/xercesimpl@2.11.0` | unknown | not_affected |
| CVE-2022-23437 | `pkg:maven/xerces/xercesimpl@2.11.0` | medium | not_affected |
| CVE-2020-14338 | `pkg:maven/xerces/xercesimpl@2.11.0` | medium | not_affected |
| CVE-2023-34055 | `pkg:maven/org.springframework.boot/spring-boot-actuator@1.5.4.RELEASE` | medium | not_affected |
| CVE-2018-14042 | `pkg:maven/org.webjars/bootstrap@3.3.6` | medium | not_affected |
| CVE-2018-14040 | `pkg:maven/org.webjars/bootstrap@3.3.6` | medium | not_affected |
| CVE-2016-10735 | `pkg:maven/org.webjars/bootstrap@3.3.6` | medium | not_affected |
| CVE-2019-8331 | `pkg:maven/org.webjars/bootstrap@3.3.6` | medium | not_affected |
| CVE-2018-20677 | `pkg:maven/org.webjars/bootstrap@3.3.6` | medium | not_affected |
| CVE-2018-20676 | `pkg:maven/org.webjars/bootstrap@3.3.6` | medium | not_affected |
| CVE-2020-15250 | `pkg:maven/junit/junit@4.12` | medium | not_affected |
| CVE-2025-48924 | `pkg:maven/commons-lang/commons-lang@2.6` | medium | not_affected |
| CVE-2025-48924 | `pkg:maven/org.apache.commons/commons-lang3@3.1` | medium | not_affected |
| CVE-2019-3797 | `pkg:maven/org.springframework.data/spring-data-jpa@1.11.4.RELEASE` | medium | not_affected |
| CVE-2019-3802 | `pkg:maven/org.springframework.data/spring-data-jpa@1.11.4.RELEASE` | medium | not_affected |
| CVE-2022-22968 | `pkg:maven/org.springframework/spring-context@4.3.9.RELEASE` | medium | not_affected |
| CVE-2024-38820 | `pkg:maven/org.springframework/spring-context@4.3.9.RELEASE` | medium | not_affected |
| CVE-2025-22233 | `pkg:maven/org.springframework/spring-context@4.3.9.RELEASE` | low | not_affected |
| CVE-2020-13956 | `pkg:maven/org.apache.httpcomponents/httpclient@4.5.3` | medium | not_affected |
| CVE-2021-29425 | `pkg:maven/commons-io/commons-io@2.4` | medium | not_affected |
| CVE-2024-47554 | `pkg:maven/commons-io/commons-io@2.4` | medium | not_affected |
| CVE-2025-49128 | `pkg:maven/com.fasterxml.jackson.core/jackson-core@2.8.8` | medium | not_affected |
| CVE-2025-52999 | `pkg:maven/com.fasterxml.jackson.core/jackson-core@2.8.8` | unknown | not_affected |

</details>

---

## Appendix: Methodology

VEX claims were generated by `VEXGenerator` from Contrast runtime library class-usage data and per-environment CVE Shield/Protect status - see `vex --help` for the exact decision policy. This advisor does not change any claim; it only assesses whether relying on each claim as generated is reasonable given the CVE's severity and exploitability.

- **sound**: the claim's justification (structural fact or active control) supports relying on it as-is
- **needs_review**: the claim rests on absence-of-observed-execution for a severe/exploitable CVE, or is otherwise borderline - a human should confirm before treating it as resolved

---

*Report generated by Contrast VEX Advisor*
*Powered by Contrast Security Runtime Observability*
