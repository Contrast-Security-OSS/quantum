<!-- Contrast VEX Advisor Report -->

# Contrast VEX Advisor
## Review of Automatically-Generated VEX Claims

---

**Report Date:** September 2, 2026
**Assessment Type:** VEX Claim Soundness Review

---

## Executive Summary

This report reviews VEX (Vulnerability Exploitability eXchange) claims generated from Contrast Security runtime library-usage and CVE Shield/Protect data. It does not re-derive whether a CVE exists - it judges whether each `not_affected`/`in_triage` claim is well-supported enough to rely on as-is, or whether a human should look at it first.

**1** application(s), **235** VEX statement(s) reviewed.

> **124 claim(s) flagged for human review** before relying on them.

### Applications

| Application | Risk Level | Statements |
|-------------|------------|------------|
| SAML-PetClinic-Demo | CRITICAL | 235 |

| Risk Level | Applications |
|------------|--------------|
| CRITICAL | 1 |

---

## Application Review

### SAML-PetClinic-Demo

**Risk Level:** CRITICAL

SAML-PetClinic-Demo has roughly 235 VEX claims spanning ~35 libraries, almost entirely 'not_affected' with either code_not_reachable (genuinely sound, ~90 claims) or 288-day duration-based absence-of-execution reasoning (~145 claims). The duration-based claims comfortably clear the 30-day policy threshold, but a large share of them cover critical/high severity CVEs -including six tied to CISA KEV entries (Spring4Shell CVE-2022-22965 x2 duration-based, Tomcat Ghostcat CVE-2020-1938, CVE-2025-24813, CVE-2017-12617, CVE-2023-44487) - so the overall posture leans on probabilistic reasoning for its riskiest findings.

**Risk Rationale:** Multiple actively-exploited (KEV) critical CVEs - notably CVE-2022-22965 (Spring4Shell) on spring-webmvc and spring-beans, and CVE-2020-1938/CVE-2025-24813/CVE-2017-12617/CVE-2023-44487 on tomcat-embed-core - are marked not_affected solely on 'no observed execution in 288 days,' not structural non-reachability, despite the libraries being substantially loaded (up to 387 of 1481 classes for tomcat, 166/498 for spring-webmvc). Dozens more critical/high jackson-databind, spring-core/web/expression, thymeleaf, and hsqldb CVEs follow the same pattern. These are exactly the claims the review criteria flag as weakest: severe, exploitable CVEs accepted on absence of evidence rather than proof of unreachability.

**Recommendation:** Prioritize human review of the KEV-tagged claims first (CVE-2022-22965 on spring-webmvc/spring-beans, CVE-2020-1938, CVE-2025-24813, CVE-2017-12617, CVE-2023-44487 on tomcat-embed-core, CVE-2018-1273 on spring-data-commons), then work through the remaining critical/high duration-only claims on jackson-databind, thymeleaf, spring-core/web/expression, hsqldb, dom4j, and mysql-connector-java. code_not_reachable claims (snakeyaml, netty, jetty-http, htmlunit, plexus-utils, commons-compress, bootstrap, junit, commons-lang/commons-lang3, commons-io, httpclient) can be trusted as-is; medium/low severity duration-based claims are acceptable without further review.

#### VEX Statements

| CVE | Library | Severity | State | Assessment |
|-----|---------|----------|-------|------------|
| CVE-2018-14721 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2018-11307 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2017-17485 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2020-8840 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2019-16335 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2019-20330 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2018-14718 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2018-14720 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2018-14719 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2020-9548 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2019-14540 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2020-9547 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2019-14892 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2019-16942 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2018-19361 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2019-16943 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2018-19360 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2018-19362 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2019-17267 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2017-7525 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2018-7489 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2019-17531 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2017-15095 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2019-14379 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | critical | not_affected | needs_review |
| CVE-2020-10673 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2020-35728 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2020-35491 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2020-35490 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2020-36184 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2020-36182 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2020-36180 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2020-36186 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2020-36181 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2020-36179 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2020-10650 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2020-36185 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2020-36188 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2020-36187 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2020-36189 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2020-36183 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2021-20190 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2018-5968 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2020-24616 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2020-24750 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2022-42004 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2022-42003 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2020-25649 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2018-12023 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2020-36518 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2019-14439 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2018-12022 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2019-12086 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | high | not_affected | needs_review |
| CVE-2019-12384 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | medium | not_affected | sound |
| CVE-2019-12814 | `pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8` | medium | not_affected | sound |
| CVE-2023-26119 | `pkg:maven/net.sourceforge.htmlunit/htmlunit@2.21` | critical | not_affected | sound |
| CVE-2020-5529 | `pkg:maven/net.sourceforge.htmlunit/htmlunit@2.21` | high | not_affected | sound |
| CVE-2020-10683 | `pkg:maven/dom4j/dom4j@1.6.1` | critical | not_affected | needs_review |
| CVE-2018-1000632 | `pkg:maven/dom4j/dom4j@1.6.1` | high | not_affected | needs_review |
| CVE-2022-1471 | `pkg:maven/org.yaml/snakeyaml@1.17` | critical | not_affected | sound |
| CVE-2022-25857 | `pkg:maven/org.yaml/snakeyaml@1.17` | high | not_affected | sound |
| CVE-2017-18640 | `pkg:maven/org.yaml/snakeyaml@1.17` | high | not_affected | sound |
| CVE-2022-38749 | `pkg:maven/org.yaml/snakeyaml@1.17` | medium | not_affected | sound |
| CVE-2022-41854 | `pkg:maven/org.yaml/snakeyaml@1.17` | medium | not_affected | sound |
| CVE-2022-38751 | `pkg:maven/org.yaml/snakeyaml@1.17` | medium | not_affected | sound |
| CVE-2022-38752 | `pkg:maven/org.yaml/snakeyaml@1.17` | medium | not_affected | sound |
| CVE-2022-38750 | `pkg:maven/org.yaml/snakeyaml@1.17` | medium | not_affected | sound |
| CVE-2022-22965 | `pkg:maven/org.springframework.boot/spring-boot-starter-web@1.5.4.RELEASE` | critical | not_affected | needs_review |
| CVE-2018-1273 | `pkg:maven/org.springframework.data/spring-data-commons@1.13.4.RELEASE` | critical | not_affected | needs_review |
| CVE-2018-1274 | `pkg:maven/org.springframework.data/spring-data-commons@1.13.4.RELEASE` | high | not_affected | needs_review |
| CVE-2026-41716 | `pkg:maven/org.springframework.data/spring-data-commons@1.13.4.RELEASE` | high | not_affected | needs_review |
| CVE-2026-41721 | `pkg:maven/org.springframework.data/spring-data-commons@1.13.4.RELEASE` | medium | not_affected | sound |
| CVE-2026-41711 | `pkg:maven/org.springframework.data/spring-data-commons@1.13.4.RELEASE` | medium | not_affected | sound |
| CVE-2018-1259 | `pkg:maven/org.springframework.data/spring-data-commons@1.13.4.RELEASE` | unknown | not_affected | sound |
| CVE-2022-41853 | `pkg:maven/org.hsqldb/hsqldb@2.3.5` | critical | not_affected | needs_review |
| CVE-2017-5929 | `pkg:maven/ch.qos.logback/logback-core@1.1.11` | critical | not_affected | needs_review |
| CVE-2023-6378 | `pkg:maven/ch.qos.logback/logback-core@1.1.11` | high | not_affected | needs_review |
| CVE-2021-42550 | `pkg:maven/ch.qos.logback/logback-core@1.1.11` | medium | not_affected | sound |
| CVE-2026-10532 | `pkg:maven/ch.qos.logback/logback-core@1.1.11` | unknown | not_affected | sound |
| CVE-2026-1225 | `pkg:maven/ch.qos.logback/logback-core@1.1.11` | unknown | not_affected | sound |
| CVE-2026-9828 | `pkg:maven/ch.qos.logback/logback-core@1.1.11` | unknown | not_affected | sound |
| CVE-2025-11226 | `pkg:maven/ch.qos.logback/logback-core@1.1.11` | unknown | not_affected | sound |
| CVE-2024-12798 | `pkg:maven/ch.qos.logback/logback-core@1.1.11` | unknown | not_affected | sound |
| CVE-2024-12801 | `pkg:maven/ch.qos.logback/logback-core@1.1.11` | unknown | not_affected | sound |
| CVE-2016-1000027 | `pkg:maven/org.springframework/spring-web@4.3.9.RELEASE` | critical | not_affected | needs_review |
| CVE-2024-22243 | `pkg:maven/org.springframework/spring-web@4.3.9.RELEASE` | high | not_affected | needs_review |
| CVE-2024-22262 | `pkg:maven/org.springframework/spring-web@4.3.9.RELEASE` | high | not_affected | needs_review |
| CVE-2024-22259 | `pkg:maven/org.springframework/spring-web@4.3.9.RELEASE` | high | not_affected | needs_review |
| CVE-2018-11039 | `pkg:maven/org.springframework/spring-web@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2024-38820 | `pkg:maven/org.springframework/spring-web@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2024-38809 | `pkg:maven/org.springframework/spring-web@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2022-22965 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | critical | not_affected | needs_review |
| CVE-2026-41842 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | high | not_affected | needs_review |
| CVE-2024-38819 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | high | not_affected | needs_review |
| CVE-2026-41845 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2026-41846 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2026-41844 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2026-41841 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2026-41843 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2026-22745 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2026-41853 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2026-22741 | `pkg:maven/org.springframework/spring-webmvc@4.3.9.RELEASE` | low | not_affected | sound |
| CVE-2017-5929 | `pkg:maven/ch.qos.logback/logback-classic@1.1.11` | critical | not_affected | needs_review |
| CVE-2023-6378 | `pkg:maven/ch.qos.logback/logback-classic@1.1.11` | high | not_affected | needs_review |
| CVE-2022-22965 | `pkg:maven/org.springframework/spring-beans@4.3.9.RELEASE` | critical | not_affected | needs_review |
| CVE-2022-22970 | `pkg:maven/org.springframework/spring-beans@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2018-8014 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | critical | not_affected | needs_review |
| CVE-2025-24813 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | critical | not_affected | needs_review |
| CVE-2026-43512 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | critical | not_affected | needs_review |
| CVE-2020-1938 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | critical | not_affected | needs_review |
| CVE-2025-31651 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | critical | not_affected | needs_review |
| CVE-2024-50379 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | critical | not_affected | needs_review |
| CVE-2026-43515 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | critical | not_affected | needs_review |
| CVE-2019-0232 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2017-12617 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2019-0199 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2018-8034 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2019-17563 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2023-46589 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2025-55752 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2026-41284 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2019-10072 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2026-43513 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2021-25122 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2024-34750 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2025-48988 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2025-49125 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2025-52434 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2022-42252 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2025-53506 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2025-52520 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2025-31650 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2024-24549 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2023-44487 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2018-1336 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2025-46701 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2019-12418 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2021-25329 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2020-9484 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | high | not_affected | needs_review |
| CVE-2018-1305 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | medium | not_affected | sound |
| CVE-2019-0221 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | medium | not_affected | sound |
| CVE-2021-24122 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | medium | not_affected | sound |
| CVE-2018-8037 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | medium | not_affected | sound |
| CVE-2018-1304 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | medium | not_affected | sound |
| CVE-2025-61795 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | medium | not_affected | sound |
| CVE-2024-21733 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | medium | not_affected | sound |
| CVE-2023-42795 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | medium | not_affected | sound |
| CVE-2018-11784 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@8.5.15` | medium | not_affected | sound |
| CVE-2017-1000487 | `pkg:maven/org.codehaus.plexus/plexus-utils@3.0.8` | critical | not_affected | sound |
| CVE-2025-67030 | `pkg:maven/org.codehaus.plexus/plexus-utils@3.0.8` | high | not_affected | sound |
| CVE-2022-4244 | `pkg:maven/org.codehaus.plexus/plexus-utils@3.0.8` | high | not_affected | sound |
| CVE-2022-4245 | `pkg:maven/org.codehaus.plexus/plexus-utils@3.0.8` | medium | not_affected | sound |
| CVE-2019-20445 | `pkg:maven/io.netty/netty@3.5.7.Final` | critical | not_affected | sound |
| CVE-2019-20444 | `pkg:maven/io.netty/netty@3.5.7.Final` | critical | not_affected | sound |
| CVE-2021-37136 | `pkg:maven/io.netty/netty@3.5.7.Final` | high | not_affected | sound |
| CVE-2021-37137 | `pkg:maven/io.netty/netty@3.5.7.Final` | high | not_affected | sound |
| CVE-2019-16869 | `pkg:maven/io.netty/netty@3.5.7.Final` | high | not_affected | sound |
| CVE-2021-43797 | `pkg:maven/io.netty/netty@3.5.7.Final` | medium | not_affected | sound |
| CVE-2021-21409 | `pkg:maven/io.netty/netty@3.5.7.Final` | medium | not_affected | sound |
| CVE-2021-21295 | `pkg:maven/io.netty/netty@3.5.7.Final` | medium | not_affected | sound |
| CVE-2021-21290 | `pkg:maven/io.netty/netty@3.5.7.Final` | medium | not_affected | sound |
| CVE-2015-2156 | `pkg:maven/io.netty/netty@3.5.7.Final` | unknown | not_affected | sound |
| CVE-2026-2332 | `pkg:maven/org.eclipse.jetty/jetty-http@9.4.5.v20170502` | critical | not_affected | sound |
| CVE-2025-11143 | `pkg:maven/org.eclipse.jetty/jetty-http@9.4.5.v20170502` | medium | not_affected | sound |
| CVE-2024-6763 | `pkg:maven/org.eclipse.jetty/jetty-http@9.4.5.v20170502` | medium | not_affected | sound |
| CVE-2023-40167 | `pkg:maven/org.eclipse.jetty/jetty-http@9.4.5.v20170502` | medium | not_affected | sound |
| CVE-2022-2047 | `pkg:maven/org.eclipse.jetty/jetty-http@9.4.5.v20170502` | low | not_affected | sound |
| CVE-2026-41901 | `pkg:maven/org.thymeleaf/thymeleaf@3.0.6.RELEASE` | critical | not_affected | needs_review |
| CVE-2026-40477 | `pkg:maven/org.thymeleaf/thymeleaf@3.0.6.RELEASE` | critical | not_affected | needs_review |
| CVE-2026-40478 | `pkg:maven/org.thymeleaf/thymeleaf@3.0.6.RELEASE` | critical | not_affected | needs_review |
| CVE-2018-3258 | `pkg:maven/mysql/mysql-connector-java@5.1.42` | high | not_affected | needs_review |
| CVE-2023-22102 | `pkg:maven/mysql/mysql-connector-java@5.1.42` | high | not_affected | needs_review |
| CVE-2019-2692 | `pkg:maven/mysql/mysql-connector-java@5.1.42` | medium | not_affected | sound |
| CVE-2022-21363 | `pkg:maven/mysql/mysql-connector-java@5.1.42` | unknown | not_affected | sound |
| CVE-2026-22733 | `pkg:maven/org.springframework.boot/spring-boot-starter-actuator@1.5.4.RELEASE` | high | not_affected | sound |
| CVE-2022-27772 | `pkg:maven/org.springframework.boot/spring-boot@1.5.4.RELEASE` | high | not_affected | needs_review |
| CVE-2025-22235 | `pkg:maven/org.springframework.boot/spring-boot@1.5.4.RELEASE` | high | not_affected | needs_review |
| CVE-2026-40973 | `pkg:maven/org.springframework.boot/spring-boot@1.5.4.RELEASE` | high | not_affected | needs_review |
| CVE-2018-1196 | `pkg:maven/org.springframework.boot/spring-boot@1.5.4.RELEASE` | medium | not_affected | sound |
| CVE-2022-28366 | `pkg:maven/net.sourceforge.htmlunit/neko-htmlunit@2.21` | high | not_affected | sound |
| CVE-2022-29546 | `pkg:maven/net.sourceforge.htmlunit/neko-htmlunit@2.21` | high | not_affected | sound |
| CVE-2022-25647 | `pkg:maven/com.google.code.gson/gson@2.8.0` | high | not_affected | needs_review |
| CVE-2021-36090 | `pkg:maven/org.apache.commons/commons-compress@1.9` | high | not_affected | sound |
| CVE-2021-35516 | `pkg:maven/org.apache.commons/commons-compress@1.9` | high | not_affected | sound |
| CVE-2021-35517 | `pkg:maven/org.apache.commons/commons-compress@1.9` | high | not_affected | sound |
| CVE-2021-35515 | `pkg:maven/org.apache.commons/commons-compress@1.9` | high | not_affected | sound |
| CVE-2024-25710 | `pkg:maven/org.apache.commons/commons-compress@1.9` | medium | not_affected | sound |
| CVE-2018-11771 | `pkg:maven/org.apache.commons/commons-compress@1.9` | medium | not_affected | sound |
| CVE-2022-34169 | `pkg:maven/xalan/xalan@2.7.2` | high | not_affected | needs_review |
| CVE-2018-1272 | `pkg:maven/org.springframework/spring-core@4.3.9.RELEASE` | high | not_affected | needs_review |
| CVE-2018-15756 | `pkg:maven/org.springframework/spring-core@4.3.9.RELEASE` | high | not_affected | needs_review |
| CVE-2026-41848 | `pkg:maven/org.springframework/spring-core@4.3.9.RELEASE` | high | not_affected | needs_review |
| CVE-2018-11040 | `pkg:maven/org.springframework/spring-core@4.3.9.RELEASE` | high | not_affected | needs_review |
| CVE-2018-1257 | `pkg:maven/org.springframework/spring-core@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2018-1271 | `pkg:maven/org.springframework/spring-core@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2018-1199 | `pkg:maven/org.springframework/spring-core@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2021-22096 | `pkg:maven/org.springframework/spring-core@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2026-41850 | `pkg:maven/org.springframework/spring-expression@4.3.9.RELEASE` | high | not_affected | needs_review |
| CVE-2026-41851 | `pkg:maven/org.springframework/spring-expression@4.3.9.RELEASE` | high | not_affected | needs_review |
| CVE-2026-41849 | `pkg:maven/org.springframework/spring-expression@4.3.9.RELEASE` | high | not_affected | needs_review |
| CVE-2023-20863 | `pkg:maven/org.springframework/spring-expression@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2023-20861 | `pkg:maven/org.springframework/spring-expression@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2022-22950 | `pkg:maven/org.springframework/spring-expression@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2026-41852 | `pkg:maven/org.springframework/spring-expression@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2024-38808 | `pkg:maven/org.springframework/spring-expression@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2023-20883 | `pkg:maven/org.springframework.boot/spring-boot-autoconfigure@1.5.4.RELEASE` | high | not_affected | needs_review |
| CVE-2024-23672 | `pkg:maven/org.apache.tomcat.embed/tomcat-embed-websocket@8.5.15` | medium | not_affected | sound |
| CVE-2020-25638 | `pkg:maven/org.hibernate/hibernate-core@5.0.4.Final` | high | not_affected | needs_review |
| CVE-2019-14900 | `pkg:maven/org.hibernate/hibernate-core@5.0.4.Final` | medium | not_affected | sound |
| CVE-2017-7536 | `pkg:maven/org.hibernate/hibernate-validator@5.3.5.Final` | high | not_affected | needs_review |
| CVE-2023-2976 | `pkg:maven/com.google.guava/guava@19.0` | high | not_affected | needs_review |
| CVE-2020-8908 | `pkg:maven/com.google.guava/guava@19.0` | low | not_affected | sound |
| CVE-2012-0881 | `pkg:maven/xerces/xercesimpl@2.11.0` | unknown | not_affected | sound |
| CVE-2013-4002 | `pkg:maven/xerces/xercesimpl@2.11.0` | unknown | not_affected | sound |
| CVE-2022-23437 | `pkg:maven/xerces/xercesimpl@2.11.0` | medium | not_affected | sound |
| CVE-2020-14338 | `pkg:maven/xerces/xercesimpl@2.11.0` | medium | not_affected | sound |
| CVE-2023-34055 | `pkg:maven/org.springframework.boot/spring-boot-actuator@1.5.4.RELEASE` | medium | not_affected | sound |
| CVE-2018-14042 | `pkg:maven/org.webjars/bootstrap@3.3.6` | medium | not_affected | sound |
| CVE-2018-14040 | `pkg:maven/org.webjars/bootstrap@3.3.6` | medium | not_affected | sound |
| CVE-2016-10735 | `pkg:maven/org.webjars/bootstrap@3.3.6` | medium | not_affected | sound |
| CVE-2019-8331 | `pkg:maven/org.webjars/bootstrap@3.3.6` | medium | not_affected | sound |
| CVE-2018-20677 | `pkg:maven/org.webjars/bootstrap@3.3.6` | medium | not_affected | sound |
| CVE-2018-20676 | `pkg:maven/org.webjars/bootstrap@3.3.6` | medium | not_affected | sound |
| CVE-2020-15250 | `pkg:maven/junit/junit@4.12` | medium | not_affected | sound |
| CVE-2025-48924 | `pkg:maven/commons-lang/commons-lang@2.6` | medium | not_affected | sound |
| CVE-2025-48924 | `pkg:maven/org.apache.commons/commons-lang3@3.1` | medium | not_affected | sound |
| CVE-2019-3797 | `pkg:maven/org.springframework.data/spring-data-jpa@1.11.4.RELEASE` | medium | not_affected | sound |
| CVE-2019-3802 | `pkg:maven/org.springframework.data/spring-data-jpa@1.11.4.RELEASE` | medium | not_affected | sound |
| CVE-2022-22968 | `pkg:maven/org.springframework/spring-context@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2024-38820 | `pkg:maven/org.springframework/spring-context@4.3.9.RELEASE` | medium | not_affected | sound |
| CVE-2025-22233 | `pkg:maven/org.springframework/spring-context@4.3.9.RELEASE` | low | not_affected | sound |
| CVE-2020-13956 | `pkg:maven/org.apache.httpcomponents/httpclient@4.5.3` | medium | not_affected | sound |
| CVE-2021-29425 | `pkg:maven/commons-io/commons-io@2.4` | medium | not_affected | sound |
| CVE-2024-47554 | `pkg:maven/commons-io/commons-io@2.4` | medium | not_affected | sound |
| CVE-2025-49128 | `pkg:maven/com.fasterxml.jackson.core/jackson-core@2.8.8` | medium | not_affected | sound |
| CVE-2025-52999 | `pkg:maven/com.fasterxml.jackson.core/jackson-core@2.8.8` | unknown | not_affected | sound |

- **CVE-2018-14721** (needs_review): Critical (10.0) jackson-databind CVE accepted purely on 288 days without observed execution, not structural unreachability.
- **CVE-2018-11307** (needs_review): Critical severity, duration-only justification on a partially-loaded library (263/582 classes).
- **CVE-2017-17485** (needs_review): Critical, EPSS 0.5 (high exploit likelihood), duration-only acceptance is weak evidence for this deserialization CVE.
- **CVE-2020-8840** (needs_review): Critical jackson-databind gadget-chain CVE relying only on absence-of-observed-execution.
- **CVE-2019-16335** (needs_review): Critical severity, duration-only reasoning, library actively loaded.
- **CVE-2019-20330** (needs_review): Critical severity accepted on runtime silence alone.
- **CVE-2018-14718** (needs_review): Critical jackson-databind deserialization CVE, duration-only justification.
- **CVE-2018-14720** (needs_review): Critical severity, no structural reachability guarantee provided.
- **CVE-2018-14719** (needs_review): Critical severity, absence-of-execution is the sole basis for not_affected.
- **CVE-2020-9548** (needs_review): Critical severity, duration-based claim on library with substantial class usage.
- **CVE-2019-14540** (needs_review): Critical severity jackson-databind CVE, duration-only reasoning.
- **CVE-2020-9547** (needs_review): Critical severity, duration-only justification.
- **CVE-2019-14892** (needs_review): Critical severity, no code_not_reachable or protected_at_runtime backing.
- **CVE-2019-16942** (needs_review): Critical severity gadget-chain CVE accepted on runtime silence alone.
- **CVE-2018-19361** (needs_review): Critical severity, duration-only reasoning.
- **CVE-2019-16943** (needs_review): Critical severity, duration-only justification.
- **CVE-2018-19360** (needs_review): Critical severity, absence-of-evidence acceptance.
- **CVE-2018-19362** (needs_review): Critical severity, duration-only justification.
- **CVE-2019-17267** (needs_review): Critical severity gadget-chain CVE, no structural guarantee.
- **CVE-2017-7525** (needs_review): Critical, EPSS 0.38, duration-only reasoning on a well-known deserialization CVE.
- **CVE-2018-7489** (needs_review): Critical severity, EPSS 0.2, duration-only justification.
- **CVE-2019-17531** (needs_review): Critical severity, no structural reachability evidence.
- **CVE-2017-15095** (needs_review): Critical severity, duration-only acceptance.
- **CVE-2019-14379** (needs_review): Critical severity jackson-databind CVE, duration-only justification.
- **CVE-2020-10673** (needs_review): High severity (8.8), duration-only reasoning without structural backing.
- **CVE-2020-35728** (needs_review): High severity, duration-only justification.
- **CVE-2020-35491** (needs_review): High severity, duration-only justification.
- **CVE-2020-35490** (needs_review): High severity, duration-only justification.
- **CVE-2020-36184** (needs_review): High severity, duration-only justification.
- **CVE-2020-36182** (needs_review): High severity, duration-only justification.
- **CVE-2020-36180** (needs_review): High severity, duration-only justification.
- **CVE-2020-36186** (needs_review): High severity, duration-only justification.
- **CVE-2020-36181** (needs_review): High severity, duration-only justification.
- **CVE-2020-36179** (needs_review): High severity, duration-only justification.
- **CVE-2020-10650** (needs_review): High severity, duration-only justification.
- **CVE-2020-36185** (needs_review): High severity, duration-only justification.
- **CVE-2020-36188** (needs_review): High severity, duration-only justification.
- **CVE-2020-36187** (needs_review): High severity, duration-only justification.
- **CVE-2020-36189** (needs_review): High severity, duration-only justification.
- **CVE-2020-36183** (needs_review): High severity, duration-only justification.
- **CVE-2021-20190** (needs_review): High severity, duration-only justification.
- **CVE-2018-5968** (needs_review): High severity, duration-only justification.
- **CVE-2020-24616** (needs_review): High severity, duration-only justification.
- **CVE-2020-24750** (needs_review): High severity, duration-only justification.
- **CVE-2022-42004** (needs_review): High severity, duration-only justification.
- **CVE-2022-42003** (needs_review): High severity, duration-only justification.
- **CVE-2020-25649** (needs_review): High severity, duration-only justification.
- **CVE-2018-12023** (needs_review): High severity, duration-only justification.
- **CVE-2020-36518** (needs_review): High severity, duration-only justification.
- **CVE-2019-14439** (needs_review): High severity, duration-only justification.
- **CVE-2018-12022** (needs_review): High severity, duration-only justification.
- **CVE-2019-12086** (needs_review): High severity, EPSS 0.22, duration-only justification.
- **CVE-2019-12384** (sound): Medium severity; duration-based acceptance is acceptable at this stakes level.
- **CVE-2019-12814** (sound): Medium severity; duration-based acceptance is reasonable.
- **CVE-2023-26119** (sound): code_not_reachable with 0 of 1295 classes loaded is a structural fact, safe regardless of critical severity.
- **CVE-2020-5529** (sound): code_not_reachable, structural non-reachability, safe to rely on.
- **CVE-2020-10683** (needs_review): Critical severity dom4j XXE CVE accepted on duration alone; only 1 of 190 classes loaded but that single class could be the vulnerable path.
- **CVE-2018-1000632** (needs_review): High severity, duration-only justification with minimal (1/190) class usage - worth confirming that one class isn't the vulnerable path.
- **CVE-2022-1471** (sound): code_not_reachable (0 of 206 classes) is structural, safe despite critical severity/EPSS 1.0.
- **CVE-2022-25857** (sound): code_not_reachable, structural non-reachability.
- **CVE-2017-18640** (sound): code_not_reachable, structural non-reachability.
- **CVE-2022-38749** (sound): code_not_reachable, medium severity, low stakes.
- **CVE-2022-41854** (sound): code_not_reachable, medium severity.
- **CVE-2022-38751** (sound): code_not_reachable, medium severity.
- **CVE-2022-38752** (sound): code_not_reachable, medium severity.
- **CVE-2022-38750** (sound): code_not_reachable, medium severity.
- **CVE-2022-22965** (needs_review): For spring-beans: Spring4Shell, critical, KEV-listed, duration-only justification with library substantially loaded (202/408 classes).
- **CVE-2018-1273** (needs_review): Critical, KEV-listed, EPSS 0.97 spring-data-commons RCE accepted purely on duration with the library substantially loaded (152/554 classes) - high priority for human review.
- **CVE-2018-1274** (needs_review): High severity, duration-only justification on same actively-loaded library.
- **CVE-2026-41716** (needs_review): High severity CVE accepted on duration alone, though EPSS is negligible.
- **CVE-2026-41721** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2026-41711** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2018-1259** (sound): Unknown/no severity score, low stakes.
- **CVE-2022-41853** (needs_review): Critical severity hsqldb CVE accepted purely on duration, library substantially loaded (229/601 classes).
- **CVE-2017-5929** (needs_review): For logback-classic: critical severity, duration-only justification with library actively loaded (63/178 classes).
- **CVE-2023-6378** (needs_review): For logback-classic: high severity, duration-only justification.
- **CVE-2021-42550** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2026-10532** (sound): Unknown severity, low stakes.
- **CVE-2026-1225** (sound): Unknown severity, low stakes.
- **CVE-2026-9828** (sound): Unknown severity, low stakes.
- **CVE-2025-11226** (sound): Unknown severity, low stakes.
- **CVE-2024-12798** (sound): Unknown severity, low stakes.
- **CVE-2024-12801** (sound): Unknown severity, low stakes.
- **CVE-2016-1000027** (needs_review): Critical severity spring-web CVE, EPSS 0.32, duration-only justification.
- **CVE-2024-22243** (needs_review): High severity, duration-only justification.
- **CVE-2024-22262** (needs_review): High severity, duration-only justification.
- **CVE-2024-22259** (needs_review): High severity, duration-only justification.
- **CVE-2018-11039** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2024-38820** (sound): For spring-context: medium severity, duration-based acceptance reasonable.
- **CVE-2024-38809** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2022-22965** (needs_review): For spring-beans: Spring4Shell, critical, KEV-listed, duration-only justification with library substantially loaded (202/408 classes).
- **CVE-2026-41842** (needs_review): High severity, duration-only justification.
- **CVE-2024-38819** (needs_review): High severity, EPSS 0.55, duration-only justification.
- **CVE-2026-41845** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2026-41846** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2026-41844** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2026-41841** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2026-41843** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2026-22745** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2026-41853** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2026-22741** (sound): Low severity, duration-based acceptance is fine.
- **CVE-2017-5929** (needs_review): For logback-classic: critical severity, duration-only justification with library actively loaded (63/178 classes).
- **CVE-2023-6378** (needs_review): For logback-classic: high severity, duration-only justification.
- **CVE-2022-22965** (needs_review): For spring-beans: Spring4Shell, critical, KEV-listed, duration-only justification with library substantially loaded (202/408 classes).
- **CVE-2022-22970** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2018-8014** (needs_review): Critical severity tomcat-embed-core CVE, duration-only justification, library heavily loaded (387/1481 classes).
- **CVE-2025-24813** (needs_review): Critical, KEV-listed, EPSS 1.0 Tomcat path equality RCE accepted purely on duration despite heavy library usage - top priority review.
- **CVE-2026-43512** (needs_review): Critical severity, duration-only justification.
- **CVE-2020-1938** (needs_review): Critical, KEV-listed (Ghostcat), EPSS 0.99, accepted purely on duration - top priority review.
- **CVE-2025-31651** (needs_review): Critical severity, duration-only justification.
- **CVE-2024-50379** (needs_review): Critical severity, EPSS 0.44, duration-only justification.
- **CVE-2026-43515** (needs_review): Critical severity, duration-only justification.
- **CVE-2019-0232** (needs_review): High severity, EPSS 1.0, duration-only justification.
- **CVE-2017-12617** (needs_review): High severity, KEV-listed, EPSS 1.0, duration-only justification - top priority review.
- **CVE-2019-0199** (needs_review): High severity, EPSS 0.73, duration-only justification.
- **CVE-2018-8034** (needs_review): High severity, duration-only justification.
- **CVE-2019-17563** (needs_review): High severity, duration-only justification.
- **CVE-2023-46589** (needs_review): High severity, duration-only justification.
- **CVE-2025-55752** (needs_review): High severity, EPSS 0.67, duration-only justification.
- **CVE-2026-41284** (needs_review): High severity, duration-only justification.
- **CVE-2019-10072** (needs_review): High severity, EPSS 0.73, duration-only justification.
- **CVE-2026-43513** (needs_review): High severity, duration-only justification.
- **CVE-2021-25122** (needs_review): High severity, duration-only justification.
- **CVE-2024-34750** (needs_review): High severity, duration-only justification.
- **CVE-2025-48988** (needs_review): High severity, EPSS 0.57, duration-only justification.
- **CVE-2025-49125** (needs_review): High severity, duration-only justification.
- **CVE-2025-52434** (needs_review): High severity, duration-only justification.
- **CVE-2022-42252** (needs_review): High severity, duration-only justification.
- **CVE-2025-53506** (needs_review): High severity, duration-only justification.
- **CVE-2025-52520** (needs_review): High severity, duration-only justification.
- **CVE-2025-31650** (needs_review): High severity, EPSS 0.6, duration-only justification.
- **CVE-2024-24549** (needs_review): High severity, EPSS 0.23, duration-only justification.
- **CVE-2023-44487** (needs_review): High severity, KEV-listed (HTTP/2 Rapid Reset), EPSS 1.0, duration-only justification - priority review.
- **CVE-2018-1336** (needs_review): High severity, duration-only justification.
- **CVE-2025-46701** (needs_review): High severity, duration-only justification.
- **CVE-2019-12418** (needs_review): High severity, duration-only justification.
- **CVE-2021-25329** (needs_review): High severity, duration-only justification.
- **CVE-2020-9484** (needs_review): High severity, EPSS 0.57, duration-only justification.
- **CVE-2018-1305** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2019-0221** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2021-24122** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2018-8037** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2018-1304** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2025-61795** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2024-21733** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2023-42795** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2018-11784** (sound): Medium severity; despite unusually high EPSS (0.94), lower stakes than critical/high per policy, acceptable on duration.
- **CVE-2017-1000487** (sound): code_not_reachable, structural non-reachability, safe despite critical severity.
- **CVE-2025-67030** (sound): code_not_reachable, structural non-reachability.
- **CVE-2022-4244** (sound): code_not_reachable, structural non-reachability.
- **CVE-2022-4245** (sound): code_not_reachable, structural non-reachability.
- **CVE-2019-20445** (sound): code_not_reachable, structural non-reachability, safe despite critical severity.
- **CVE-2019-20444** (sound): code_not_reachable, structural non-reachability.
- **CVE-2021-37136** (sound): code_not_reachable, structural non-reachability.
- **CVE-2021-37137** (sound): code_not_reachable, structural non-reachability.
- **CVE-2019-16869** (sound): code_not_reachable, structural non-reachability.
- **CVE-2021-43797** (sound): code_not_reachable, structural non-reachability.
- **CVE-2021-21409** (sound): code_not_reachable, structural non-reachability.
- **CVE-2021-21295** (sound): code_not_reachable, structural non-reachability.
- **CVE-2021-21290** (sound): code_not_reachable, structural non-reachability.
- **CVE-2015-2156** (sound): code_not_reachable, structural non-reachability.
- **CVE-2026-2332** (sound): code_not_reachable, structural non-reachability, safe despite critical severity.
- **CVE-2025-11143** (sound): code_not_reachable, structural non-reachability.
- **CVE-2024-6763** (sound): code_not_reachable, structural non-reachability.
- **CVE-2023-40167** (sound): code_not_reachable, structural non-reachability.
- **CVE-2022-2047** (sound): code_not_reachable, structural non-reachability.
- **CVE-2026-41901** (needs_review): Critical severity thymeleaf CVE, duration-only justification, library heavily loaded (367/549 classes).
- **CVE-2026-40477** (needs_review): Critical severity, duration-only justification.
- **CVE-2026-40478** (needs_review): Critical severity, duration-only justification.
- **CVE-2018-3258** (needs_review): High severity mysql-connector CVE, duration-only justification.
- **CVE-2023-22102** (needs_review): High severity, duration-only justification.
- **CVE-2019-2692** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2022-21363** (sound): Unknown severity, low stakes.
- **CVE-2026-22733** (sound): code_not_reachable (0 of 0 classes), consistent with starter POM containing no code, safe despite high severity.
- **CVE-2022-27772** (needs_review): High severity spring-boot CVE, duration-only justification.
- **CVE-2025-22235** (needs_review): High severity, duration-only justification.
- **CVE-2026-40973** (needs_review): High severity, duration-only justification.
- **CVE-2018-1196** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2022-28366** (sound): code_not_reachable, structural non-reachability.
- **CVE-2022-29546** (sound): code_not_reachable, structural non-reachability.
- **CVE-2022-25647** (needs_review): High severity gson CVE, duration-only justification with library actively loaded (36/174 classes).
- **CVE-2021-36090** (sound): code_not_reachable, structural non-reachability.
- **CVE-2021-35516** (sound): code_not_reachable, structural non-reachability.
- **CVE-2021-35517** (sound): code_not_reachable, structural non-reachability.
- **CVE-2021-35515** (sound): code_not_reachable, structural non-reachability.
- **CVE-2024-25710** (sound): code_not_reachable, medium severity.
- **CVE-2018-11771** (sound): code_not_reachable, medium severity.
- **CVE-2022-34169** (needs_review): High severity, EPSS 0.81 xalan CVE, duration-only justification despite very low class usage (7/1501) - worth confirming those 7 classes aren't the vulnerable path.
- **CVE-2018-1272** (needs_review): High severity spring-core CVE, duration-only justification, library heavily loaded (334/791 classes).
- **CVE-2018-15756** (needs_review): High severity, duration-only justification.
- **CVE-2026-41848** (needs_review): High severity, duration-only justification.
- **CVE-2018-11040** (needs_review): High severity, duration-only justification.
- **CVE-2018-1257** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2018-1271** (sound): Medium severity, duration-based acceptance reasonable despite elevated EPSS (0.35).
- **CVE-2018-1199** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2021-22096** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2026-41850** (needs_review): High severity spring-expression CVE, duration-only justification, library heavily loaded (91/142 classes).
- **CVE-2026-41851** (needs_review): High severity, duration-only justification.
- **CVE-2026-41849** (needs_review): High severity, duration-only justification.
- **CVE-2023-20863** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2023-20861** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2022-22950** (sound): Medium severity, duration-based acceptance reasonable despite EPSS 0.36.
- **CVE-2026-41852** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2024-38808** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2023-20883** (needs_review): High severity spring-boot-autoconfigure CVE, duration-only justification, library well-loaded (195/848 classes).
- **CVE-2024-23672** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2020-25638** (needs_review): High severity hibernate-core CVE, duration-only justification, library heavily loaded (1563/3787 classes).
- **CVE-2019-14900** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2017-7536** (needs_review): High severity hibernate-validator CVE, duration-only justification, library well-loaded (225/459 classes).
- **CVE-2023-2976** (needs_review): High severity guava CVE, duration-only justification, though usage is minimal (5/1717 classes).
- **CVE-2020-8908** (sound): Low severity, duration-based acceptance reasonable.
- **CVE-2012-0881** (sound): Unknown severity, low stakes.
- **CVE-2013-4002** (sound): Unknown severity, low stakes.
- **CVE-2022-23437** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2020-14338** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2023-34055** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2018-14042** (sound): code_not_reachable, structural non-reachability.
- **CVE-2018-14040** (sound): code_not_reachable, structural non-reachability.
- **CVE-2016-10735** (sound): code_not_reachable, structural non-reachability.
- **CVE-2019-8331** (sound): code_not_reachable, structural non-reachability.
- **CVE-2018-20677** (sound): code_not_reachable, structural non-reachability.
- **CVE-2018-20676** (sound): code_not_reachable, structural non-reachability.
- **CVE-2020-15250** (sound): code_not_reachable, structural non-reachability (test-scope library).
- **CVE-2025-48924** (sound): For commons-lang3: code_not_reachable, structural non-reachability.
- **CVE-2025-48924** (sound): For commons-lang3: code_not_reachable, structural non-reachability.
- **CVE-2019-3797** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2019-3802** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2022-22968** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2024-38820** (sound): For spring-context: medium severity, duration-based acceptance reasonable.
- **CVE-2025-22233** (sound): Low severity, duration-based acceptance reasonable.
- **CVE-2020-13956** (sound): code_not_reachable, structural non-reachability.
- **CVE-2021-29425** (sound): code_not_reachable, structural non-reachability.
- **CVE-2024-47554** (sound): code_not_reachable, structural non-reachability.
- **CVE-2025-49128** (sound): Medium severity, duration-based acceptance reasonable.
- **CVE-2025-52999** (sound): Unknown severity, low stakes.

---

## Appendix: Methodology

VEX claims were generated by `VEXGenerator` from Contrast runtime library class-usage data and per-environment CVE Shield/Protect status - see `vex --help` for the exact decision policy. This advisor does not change any claim; it only assesses whether relying on each claim as generated is reasonable given the CVE's severity and exploitability.

- **sound**: the claim's justification (structural fact or active control) supports relying on it as-is
- **needs_review**: the claim rests on absence-of-observed-execution for a severe/exploitable CVE, or is otherwise borderline - a human should confirm before treating it as resolved

---

*Report generated by Contrast VEX Advisor*
*Powered by Contrast Security Runtime Observability*
