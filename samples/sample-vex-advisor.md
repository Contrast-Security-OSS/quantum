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

- **125 of 235 claim(s) flagged for human review** before relying on them.
- **8 flagged claim(s) are on CVEs in the CISA Known Exploited Vulnerabilities (KEV) catalog** - actively exploited in the wild: CVE-2022-22965, CVE-2018-1273, CVE-2025-24813, CVE-2020-1938, CVE-2017-12617, CVE-2023-44487.
- **10 flagged claim(s) have an EPSS score ≥ 0.5** (50%+ predicted exploitation likelihood): CVE-2017-17485, CVE-2024-38819, CVE-2019-0232, CVE-2019-0199, CVE-2025-55752, CVE-2019-10072 (+4 more).
- Application(s) rated CRITICAL/HIGH risk: SAML-PetClinic-Demo.

### Applications

| Application | Risk Level | Statements |
|-------------|------------|------------|
| SAML-PetClinic-Demo | CRITICAL | 235 |

| Risk Level | Applications |
|------------|--------------|
| CRITICAL | 1 |

### Legend

**VEX** - `NA` = not_affected, `IT` = in_triage

**Rationale code:**

| Code | Meaning |
|------|---------|
| `UNU` | Unused - library never loaded at runtime (0 classes) |
| `SHD` | Shielded - CVE Shield/Protect actively mitigating at runtime |
| `AGD` | Aged out - not_affected on duration alone (no observed execution past the acceptance threshold) |
| `WCH` | Watching - in_triage, still within the acceptance window |
| `!` suffix | Flagged `needs_review` by the VEX Advisor - see the app's Risk Rationale above |

---

## Application Detail

### SAML-PetClinic-Demo

**Risk Level:** CRITICAL

SAML-PetClinic-Demo has 235 VEX claims across roughly 40 libraries, most on jackson-databind 2.8.8, tomcat-embed-core 8.5.15, and the Spring 4.3.9/1.5.4 stack. About a third of claims rest on solid code_not_reachable (zero classes loaded) evidence and are safe to trust as-is; the rest, covering dozens of critical/high CVEs including three separate Spring4Shell (CVE-2022-22965) instances and Tomcat Ghostcat/rapid-reset KEV entries, are accepted purely on 288 days of no observed execution in a library that is otherwise heavily loaded and used.

**Risk Rationale:** Several KEV-listed, high-EPSS critical CVEs (CVE-2022-22965 Spring4Shell across spring-data-commons/spring-webmvc/spring-beans, CVE-2020-1938 Ghostcat, CVE-2025-24813, CVE-2017-12617, CVE-2023-44487) are marked not_affected using only duration-based absence-of-execution reasoning on libraries that are substantially loaded (100-1500+ classes in use), not structurally unreachable. Combined with the huge number of critical/high jackson-databind CVEs accepted the same way on a library with 263 of 582 classes actively used, this VEX set is not safe to rely on wholesale without human reachability verification on the flagged items.

**Recommendation:** Prioritize manual review of the KEV/high-EPSS duration-only claims first: CVE-2022-22965 (spring-data-commons, spring-webmvc, spring-beans), CVE-2020-1938 and CVE-2017-12617 and CVE-2023-44487 and CVE-2025-24813 (tomcat-embed-core), and CVE-2018-1273 (spring-data-commons). Then work through the remaining critical/high jackson-databind, tomcat-embed-core, spring-web/-core/-expression, dom4j, hsqldb, logback, thymeleaf, mysql-connector-java, hibernate, guava, gson, and xalan claims flagged needs_review, ideally by confirming route-level reachability rather than relying on elapsed-time-without-execution. The code_not_reachable claims (snakeyaml, netty, jetty-http, plexus-utils, commons-compress, bootstrap, junit, commons-lang/-lang3, commons-io, httpclient, neko-htmlunit, htmlunit, spring-boot-starter-web/-actuator) can be trusted as-is.

| CVE | Library | Score | VEX | Rationale |
|-----|---------|-------|-----|-----------|
| CVE-2018-14721 | jackson-databind@2.8.8 | 10.0 | NA | AGD! |
| CVE-2018-11307 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2017-17485 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2020-8840 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2019-16335 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2019-20330 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2018-14718 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2018-14720 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2018-14719 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2020-9548 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2019-14540 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2020-9547 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2019-14892 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2019-16942 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2018-19361 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2019-16943 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2018-19360 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2018-19362 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2019-17267 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2017-7525 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2018-7489 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2019-17531 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2017-15095 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2019-14379 | jackson-databind@2.8.8 | 9.8 | NA | AGD! |
| CVE-2020-10683 | dom4j@1.6.1 | 9.8 | NA | AGD! |
| CVE-2022-22965 | spring-boot-starter-web@1.5.4.RELEASE | 9.8 | NA | UNU! |
| CVE-2018-1273 | spring-data-commons@1.13.4.RELEASE | 9.8 | NA | AGD! |
| CVE-2022-41853 | hsqldb@2.3.5 | 9.8 | NA | AGD! |
| CVE-2017-5929 | logback-core@1.1.11 | 9.8 | NA | AGD! |
| CVE-2016-1000027 | spring-web@4.3.9.RELEASE | 9.8 | NA | AGD! |
| CVE-2022-22965 | spring-webmvc@4.3.9.RELEASE | 9.8 | NA | AGD! |
| CVE-2017-5929 | logback-classic@1.1.11 | 9.8 | NA | AGD! |
| CVE-2022-22965 | spring-beans@4.3.9.RELEASE | 9.8 | NA | AGD! |
| CVE-2018-8014 | tomcat-embed-core@8.5.15 | 9.8 | NA | AGD! |
| CVE-2025-24813 | tomcat-embed-core@8.5.15 | 9.8 | NA | AGD! |
| CVE-2026-43512 | tomcat-embed-core@8.5.15 | 9.8 | NA | AGD! |
| CVE-2020-1938 | tomcat-embed-core@8.5.15 | 9.8 | NA | AGD! |
| CVE-2025-31651 | tomcat-embed-core@8.5.15 | 9.8 | NA | AGD! |
| CVE-2024-50379 | tomcat-embed-core@8.5.15 | 9.8 | NA | AGD! |
| CVE-2026-43515 | tomcat-embed-core@8.5.15 | 9.1 | NA | AGD! |
| CVE-2026-41901 | thymeleaf@3.0.6.RELEASE | 9.0 | NA | AGD! |
| CVE-2026-40477 | thymeleaf@3.0.6.RELEASE | 9.0 | NA | AGD! |
| CVE-2026-40478 | thymeleaf@3.0.6.RELEASE | 9.0 | NA | AGD! |
| CVE-2020-10673 | jackson-databind@2.8.8 | 8.8 | NA | AGD! |
| CVE-2020-35728 | jackson-databind@2.8.8 | 8.1 | NA | AGD! |
| CVE-2020-35491 | jackson-databind@2.8.8 | 8.1 | NA | AGD! |
| CVE-2020-35490 | jackson-databind@2.8.8 | 8.1 | NA | AGD! |
| CVE-2020-36184 | jackson-databind@2.8.8 | 8.1 | NA | AGD! |
| CVE-2020-36182 | jackson-databind@2.8.8 | 8.1 | NA | AGD! |
| CVE-2020-36180 | jackson-databind@2.8.8 | 8.1 | NA | AGD! |
| CVE-2020-36186 | jackson-databind@2.8.8 | 8.1 | NA | AGD! |
| CVE-2020-36181 | jackson-databind@2.8.8 | 8.1 | NA | AGD! |
| CVE-2020-36179 | jackson-databind@2.8.8 | 8.1 | NA | AGD! |
| CVE-2020-10650 | jackson-databind@2.8.8 | 8.1 | NA | AGD! |
| CVE-2020-36185 | jackson-databind@2.8.8 | 8.1 | NA | AGD! |
| CVE-2020-36188 | jackson-databind@2.8.8 | 8.1 | NA | AGD! |
| CVE-2020-36187 | jackson-databind@2.8.8 | 8.1 | NA | AGD! |
| CVE-2020-36189 | jackson-databind@2.8.8 | 8.1 | NA | AGD! |
| CVE-2020-36183 | jackson-databind@2.8.8 | 8.1 | NA | AGD! |
| CVE-2021-20190 | jackson-databind@2.8.8 | 8.1 | NA | AGD! |
| CVE-2018-5968 | jackson-databind@2.8.8 | 8.1 | NA | AGD! |
| CVE-2020-24616 | jackson-databind@2.8.8 | 8.1 | NA | AGD! |
| CVE-2020-24750 | jackson-databind@2.8.8 | 8.1 | NA | AGD! |
| CVE-2022-42004 | jackson-databind@2.8.8 | 7.5 | NA | AGD! |
| CVE-2022-42003 | jackson-databind@2.8.8 | 7.5 | NA | AGD! |
| CVE-2020-25649 | jackson-databind@2.8.8 | 7.5 | NA | AGD! |
| CVE-2018-12023 | jackson-databind@2.8.8 | 7.5 | NA | AGD! |
| CVE-2020-36518 | jackson-databind@2.8.8 | 7.5 | NA | AGD! |
| CVE-2019-14439 | jackson-databind@2.8.8 | 7.5 | NA | AGD! |
| CVE-2018-12022 | jackson-databind@2.8.8 | 7.5 | NA | AGD! |
| CVE-2019-12086 | jackson-databind@2.8.8 | 7.5 | NA | AGD! |
| CVE-2018-1000632 | dom4j@1.6.1 | 7.5 | NA | AGD! |
| CVE-2018-1274 | spring-data-commons@1.13.4.RELEASE | 7.5 | NA | AGD! |
| CVE-2026-41716 | spring-data-commons@1.13.4.RELEASE | 7.5 | NA | AGD! |
| CVE-2023-6378 | logback-core@1.1.11 | 7.5 | NA | AGD! |
| CVE-2024-22243 | spring-web@4.3.9.RELEASE | 8.1 | NA | AGD! |
| CVE-2024-22262 | spring-web@4.3.9.RELEASE | 8.1 | NA | AGD! |
| CVE-2024-22259 | spring-web@4.3.9.RELEASE | 8.1 | NA | AGD! |
| CVE-2026-41842 | spring-webmvc@4.3.9.RELEASE | 7.5 | NA | AGD! |
| CVE-2024-38819 | spring-webmvc@4.3.9.RELEASE | 7.5 | NA | AGD! |
| CVE-2023-6378 | logback-classic@1.1.11 | 7.5 | NA | AGD! |
| CVE-2019-0232 | tomcat-embed-core@8.5.15 | 8.1 | NA | AGD! |
| CVE-2017-12617 | tomcat-embed-core@8.5.15 | 8.1 | NA | AGD! |
| CVE-2019-0199 | tomcat-embed-core@8.5.15 | 7.5 | NA | AGD! |
| CVE-2018-8034 | tomcat-embed-core@8.5.15 | 7.5 | NA | AGD! |
| CVE-2019-17563 | tomcat-embed-core@8.5.15 | 7.5 | NA | AGD! |
| CVE-2023-46589 | tomcat-embed-core@8.5.15 | 7.5 | NA | AGD! |
| CVE-2025-55752 | tomcat-embed-core@8.5.15 | 7.5 | NA | AGD! |
| CVE-2026-41284 | tomcat-embed-core@8.5.15 | 7.5 | NA | AGD! |
| CVE-2019-10072 | tomcat-embed-core@8.5.15 | 7.5 | NA | AGD! |
| CVE-2026-43513 | tomcat-embed-core@8.5.15 | 7.5 | NA | AGD! |
| CVE-2021-25122 | tomcat-embed-core@8.5.15 | 7.5 | NA | AGD! |
| CVE-2024-34750 | tomcat-embed-core@8.5.15 | 7.5 | NA | AGD! |
| CVE-2025-48988 | tomcat-embed-core@8.5.15 | 7.5 | NA | AGD! |
| CVE-2025-49125 | tomcat-embed-core@8.5.15 | 7.5 | NA | AGD! |
| CVE-2025-52434 | tomcat-embed-core@8.5.15 | 7.5 | NA | AGD! |
| CVE-2022-42252 | tomcat-embed-core@8.5.15 | 7.5 | NA | AGD! |
| CVE-2025-53506 | tomcat-embed-core@8.5.15 | 7.5 | NA | AGD! |
| CVE-2025-52520 | tomcat-embed-core@8.5.15 | 7.5 | NA | AGD! |
| CVE-2025-31650 | tomcat-embed-core@8.5.15 | 7.5 | NA | AGD! |
| CVE-2024-24549 | tomcat-embed-core@8.5.15 | 7.5 | NA | AGD! |
| CVE-2023-44487 | tomcat-embed-core@8.5.15 | 7.5 | NA | AGD! |
| CVE-2018-1336 | tomcat-embed-core@8.5.15 | 7.5 | NA | AGD! |
| CVE-2025-46701 | tomcat-embed-core@8.5.15 | 7.3 | NA | AGD! |
| CVE-2019-12418 | tomcat-embed-core@8.5.15 | 7.0 | NA | AGD! |
| CVE-2021-25329 | tomcat-embed-core@8.5.15 | 7.0 | NA | AGD! |
| CVE-2020-9484 | tomcat-embed-core@8.5.15 | 7.0 | NA | AGD! |
| CVE-2018-3258 | mysql-connector-java@5.1.42 | 8.8 | NA | AGD! |
| CVE-2023-22102 | mysql-connector-java@5.1.42 | 8.3 | NA | AGD! |
| CVE-2022-27772 | spring-boot@1.5.4.RELEASE | 7.8 | NA | AGD! |
| CVE-2025-22235 | spring-boot@1.5.4.RELEASE | 7.3 | NA | AGD! |
| CVE-2026-40973 | spring-boot@1.5.4.RELEASE | 7.0 | NA | AGD! |
| CVE-2022-25647 | gson@2.8.0 | 7.5 | NA | AGD! |
| CVE-2022-34169 | xalan@2.7.2 | 7.5 | NA | AGD! |
| CVE-2018-1272 | spring-core@4.3.9.RELEASE | 7.5 | NA | AGD! |
| CVE-2018-15756 | spring-core@4.3.9.RELEASE | 7.5 | NA | AGD! |
| CVE-2026-41848 | spring-core@4.3.9.RELEASE | 7.5 | NA | AGD! |
| CVE-2018-11040 | spring-core@4.3.9.RELEASE | 7.5 | NA | AGD! |
| CVE-2026-41850 | spring-expression@4.3.9.RELEASE | 7.5 | NA | AGD! |
| CVE-2026-41851 | spring-expression@4.3.9.RELEASE | 7.5 | NA | AGD! |
| CVE-2026-41849 | spring-expression@4.3.9.RELEASE | 7.5 | NA | AGD! |
| CVE-2023-20883 | spring-boot-autoconfigure@1.5.4.RELEASE | 7.5 | NA | AGD! |
| CVE-2020-25638 | hibernate-core@5.0.4.Final | 7.4 | NA | AGD! |
| CVE-2017-7536 | hibernate-validator@5.3.5.Final | 7.0 | NA | AGD! |
| CVE-2023-2976 | guava@19.0 | 7.1 | NA | AGD! |
| CVE-2023-26119 | htmlunit@2.21 | 9.8 | NA | UNU |
| CVE-2022-1471 | snakeyaml@1.17 | 9.8 | NA | UNU |
| CVE-2017-1000487 | plexus-utils@3.0.8 | 9.8 | NA | UNU |
| CVE-2019-20445 | netty@3.5.7.Final | 9.1 | NA | UNU |
| CVE-2019-20444 | netty@3.5.7.Final | 9.1 | NA | UNU |
| CVE-2026-2332 | jetty-http@9.4.5.v20170502 | 9.1 | NA | UNU |
| CVE-2020-5529 | htmlunit@2.21 | 8.1 | NA | UNU |
| CVE-2022-25857 | snakeyaml@1.17 | 7.5 | NA | UNU |
| CVE-2017-18640 | snakeyaml@1.17 | 7.5 | NA | UNU |
| CVE-2025-67030 | plexus-utils@3.0.8 | 8.8 | NA | UNU |
| CVE-2022-4244 | plexus-utils@3.0.8 | 7.5 | NA | UNU |
| CVE-2021-37136 | netty@3.5.7.Final | 7.5 | NA | UNU |
| CVE-2021-37137 | netty@3.5.7.Final | 7.5 | NA | UNU |
| CVE-2019-16869 | netty@3.5.7.Final | 7.5 | NA | UNU |
| CVE-2026-22733 | spring-boot-starter-actuator@1.5.4.RELEASE | 8.1 | NA | UNU |
| CVE-2022-28366 | neko-htmlunit@2.21 | 7.5 | NA | UNU |
| CVE-2022-29546 | neko-htmlunit@2.21 | 7.5 | NA | UNU |
| CVE-2021-36090 | commons-compress@1.9 | 7.5 | NA | UNU |
| CVE-2021-35516 | commons-compress@1.9 | 7.5 | NA | UNU |
| CVE-2021-35517 | commons-compress@1.9 | 7.5 | NA | UNU |
| CVE-2021-35515 | commons-compress@1.9 | 7.5 | NA | UNU |
| CVE-2019-12384 | jackson-databind@2.8.8 | 5.9 | NA | AGD |
| CVE-2019-12814 | jackson-databind@2.8.8 | 5.9 | NA | AGD |
| CVE-2022-38749 | snakeyaml@1.17 | 6.5 | NA | UNU |
| CVE-2022-41854 | snakeyaml@1.17 | 6.5 | NA | UNU |
| CVE-2022-38751 | snakeyaml@1.17 | 6.5 | NA | UNU |
| CVE-2022-38752 | snakeyaml@1.17 | 6.5 | NA | UNU |
| CVE-2022-38750 | snakeyaml@1.17 | 5.5 | NA | UNU |
| CVE-2026-41721 | spring-data-commons@1.13.4.RELEASE | 5.9 | NA | AGD |
| CVE-2026-41711 | spring-data-commons@1.13.4.RELEASE | 5.9 | NA | AGD |
| CVE-2021-42550 | logback-core@1.1.11 | 6.6 | NA | AGD |
| CVE-2018-11039 | spring-web@4.3.9.RELEASE | 5.9 | NA | AGD |
| CVE-2024-38820 | spring-web@4.3.9.RELEASE | 5.3 | NA | AGD |
| CVE-2024-38809 | spring-web@4.3.9.RELEASE | 5.3 | NA | AGD |
| CVE-2026-41845 | spring-webmvc@4.3.9.RELEASE | 6.1 | NA | AGD |
| CVE-2026-41846 | spring-webmvc@4.3.9.RELEASE | 6.1 | NA | AGD |
| CVE-2026-41844 | spring-webmvc@4.3.9.RELEASE | 6.1 | NA | AGD |
| CVE-2026-41841 | spring-webmvc@4.3.9.RELEASE | 5.9 | NA | AGD |
| CVE-2026-41843 | spring-webmvc@4.3.9.RELEASE | 5.9 | NA | AGD |
| CVE-2026-22745 | spring-webmvc@4.3.9.RELEASE | 5.3 | NA | AGD |
| CVE-2026-41853 | spring-webmvc@4.3.9.RELEASE | 5.3 | NA | AGD |
| CVE-2022-22970 | spring-beans@4.3.9.RELEASE | 5.3 | NA | AGD |
| CVE-2018-1305 | tomcat-embed-core@8.5.15 | 6.5 | NA | AGD |
| CVE-2019-0221 | tomcat-embed-core@8.5.15 | 6.1 | NA | AGD |
| CVE-2021-24122 | tomcat-embed-core@8.5.15 | 5.9 | NA | AGD |
| CVE-2018-8037 | tomcat-embed-core@8.5.15 | 5.9 | NA | AGD |
| CVE-2018-1304 | tomcat-embed-core@8.5.15 | 5.9 | NA | AGD |
| CVE-2025-61795 | tomcat-embed-core@8.5.15 | 5.3 | NA | AGD |
| CVE-2024-21733 | tomcat-embed-core@8.5.15 | 5.3 | NA | AGD |
| CVE-2023-42795 | tomcat-embed-core@8.5.15 | 5.3 | NA | AGD |
| CVE-2018-11784 | tomcat-embed-core@8.5.15 | 4.3 | NA | AGD |
| CVE-2022-4245 | plexus-utils@3.0.8 | 4.3 | NA | UNU |
| CVE-2021-43797 | netty@3.5.7.Final | 6.5 | NA | UNU |
| CVE-2021-21409 | netty@3.5.7.Final | 5.9 | NA | UNU |
| CVE-2021-21295 | netty@3.5.7.Final | 5.9 | NA | UNU |
| CVE-2021-21290 | netty@3.5.7.Final | 5.5 | NA | UNU |
| CVE-2025-11143 | jetty-http@9.4.5.v20170502 | 6.5 | NA | UNU |
| CVE-2024-6763 | jetty-http@9.4.5.v20170502 | 5.3 | NA | UNU |
| CVE-2023-40167 | jetty-http@9.4.5.v20170502 | 5.3 | NA | UNU |
| CVE-2019-2692 | mysql-connector-java@5.1.42 | 6.3 | NA | AGD |
| CVE-2018-1196 | spring-boot@1.5.4.RELEASE | 5.9 | NA | AGD |
| CVE-2024-25710 | commons-compress@1.9 | 5.5 | NA | UNU |
| CVE-2018-11771 | commons-compress@1.9 | 5.5 | NA | UNU |
| CVE-2018-1257 | spring-core@4.3.9.RELEASE | 6.5 | NA | AGD |
| CVE-2018-1271 | spring-core@4.3.9.RELEASE | 5.9 | NA | AGD |
| CVE-2018-1199 | spring-core@4.3.9.RELEASE | 5.3 | NA | AGD |
| CVE-2021-22096 | spring-core@4.3.9.RELEASE | 4.3 | NA | AGD |
| CVE-2023-20863 | spring-expression@4.3.9.RELEASE | 6.5 | NA | AGD |
| CVE-2023-20861 | spring-expression@4.3.9.RELEASE | 6.5 | NA | AGD |
| CVE-2022-22950 | spring-expression@4.3.9.RELEASE | 6.5 | NA | AGD |
| CVE-2026-41852 | spring-expression@4.3.9.RELEASE | 5.3 | NA | AGD |
| CVE-2024-38808 | spring-expression@4.3.9.RELEASE | 4.3 | NA | AGD |
| CVE-2024-23672 | tomcat-embed-websocket@8.5.15 | 6.3 | NA | AGD |
| CVE-2019-14900 | hibernate-core@5.0.4.Final | 6.5 | NA | AGD |
| CVE-2022-23437 | xercesimpl@2.11.0 | 6.5 | NA | AGD |
| CVE-2020-14338 | xercesimpl@2.11.0 | 5.3 | NA | AGD |
| CVE-2023-34055 | spring-boot-actuator@1.5.4.RELEASE | 6.5 | NA | AGD |
| CVE-2018-14042 | bootstrap@3.3.6 | 6.1 | NA | UNU |
| CVE-2018-14040 | bootstrap@3.3.6 | 6.1 | NA | UNU |
| CVE-2016-10735 | bootstrap@3.3.6 | 6.1 | NA | UNU |
| CVE-2019-8331 | bootstrap@3.3.6 | 6.1 | NA | UNU |
| CVE-2018-20677 | bootstrap@3.3.6 | 6.1 | NA | UNU |
| CVE-2018-20676 | bootstrap@3.3.6 | 6.1 | NA | UNU |
| CVE-2020-15250 | junit@4.12 | 5.5 | NA | UNU |
| CVE-2025-48924 | commons-lang@2.6 | 5.3 | NA | UNU |
| CVE-2025-48924 | commons-lang3@3.1 | 5.3 | NA | UNU |
| CVE-2019-3797 | spring-data-jpa@1.11.4.RELEASE | 5.3 | NA | AGD |
| CVE-2019-3802 | spring-data-jpa@1.11.4.RELEASE | 5.3 | NA | AGD |
| CVE-2022-22968 | spring-context@4.3.9.RELEASE | 5.3 | NA | AGD |
| CVE-2024-38820 | spring-context@4.3.9.RELEASE | 5.3 | NA | AGD |
| CVE-2020-13956 | httpclient@4.5.3 | 5.3 | NA | UNU |
| CVE-2021-29425 | commons-io@2.4 | 4.8 | NA | UNU |
| CVE-2024-47554 | commons-io@2.4 | 4.3 | NA | UNU |
| CVE-2025-49128 | jackson-core@2.8.8 | 4.0 | NA | AGD |
| CVE-2026-22741 | spring-webmvc@4.3.9.RELEASE | 3.1 | NA | AGD |
| CVE-2022-2047 | jetty-http@9.4.5.v20170502 | 2.7 | NA | UNU |
| CVE-2020-8908 | guava@19.0 | 3.3 | NA | AGD |
| CVE-2025-22233 | spring-context@4.3.9.RELEASE | 3.1 | NA | AGD |
| CVE-2018-1259 | spring-data-commons@1.13.4.RELEASE | 0.0 | NA | AGD |
| CVE-2026-10532 | logback-core@1.1.11 | 0.0 | NA | AGD |
| CVE-2026-1225 | logback-core@1.1.11 | 0.0 | NA | AGD |
| CVE-2026-9828 | logback-core@1.1.11 | 0.0 | NA | AGD |
| CVE-2025-11226 | logback-core@1.1.11 | 0.0 | NA | AGD |
| CVE-2024-12798 | logback-core@1.1.11 | 0.0 | NA | AGD |
| CVE-2024-12801 | logback-core@1.1.11 | 0.0 | NA | AGD |
| CVE-2015-2156 | netty@3.5.7.Final | 0.0 | NA | UNU |
| CVE-2022-21363 | mysql-connector-java@5.1.42 | 0.0 | NA | AGD |
| CVE-2012-0881 | xercesimpl@2.11.0 | 0.0 | NA | AGD |
| CVE-2013-4002 | xercesimpl@2.11.0 | 0.0 | NA | AGD |
| CVE-2025-52999 | jackson-core@2.8.8 | 0.0 | NA | AGD |

---

## Appendix: Methodology

VEX claims were generated by `VEXGenerator` from Contrast runtime library class-usage data and per-environment CVE Shield/Protect status - see `vex --help` for the exact decision policy. This advisor does not change any claim; it only assesses whether relying on each claim as generated is reasonable given the CVE's severity and exploitability. See the Legend above for the VEX/Rationale codes used in the per-application tables.

- **sound** (no `!`): the claim's justification (structural fact or active control) supports relying on it as-is
- **needs_review** (`!` suffix): the claim rests on absence-of-observed-execution for a severe/exploitable CVE, or is otherwise borderline - a human should confirm before treating it as resolved

---

*Report generated by Contrast VEX Advisor*
*Powered by Contrast Security Runtime Observability*
