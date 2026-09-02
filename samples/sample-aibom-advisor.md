<!-- Contrast AI Advisor Report -->

# Contrast AI Advisor
## Inventory of AI-Enabled Applications

---

**Client:** Contrast AI Usage Inventory
**Report Date:** September 2, 2026
**Assessment Type:** Runtime AI/LLM Usage Inventory & Governance Risk Assessment

---

## Executive Summary

This report inventories every AI/LLM model and provider observed actually running in production across your applications - the model, provider, destination endpoint, and real call stack behind each usage, captured by Contrast Security's runtime instrumentation.

**2** application(s) use AI, calling **1** distinct model(s) across **1** provider(s), for **2** total usage instance(s).

> No applications were flagged CRITICAL or HIGH risk for their AI usage.

### Applications

| Application | Risk Level | Models Used |
|-------------|------------|--------------|
| Robert-cargocats-aiservice | LOW | `smollm2:135m-tuned` |
| Robert-cargocats-reportservice | LOW | `smollm2:135m-tuned` |

### Models & Providers

| Provider | Model | Host Category | Applications | Invocations |
|----------|-------|----------------|---------------|-------------|
| openai | `smollm2:135m-tuned` | local | 2 | 2 |

- **1** model(s) self-hosted/local (no external data egress)

| Risk Level | Applications |
|------------|--------------|
| LOW | 2 |

---

## Application Inventory

### Robert-cargocats-aiservice

**Risk Level:** LOW

**Language:** JAVA | **Posture Score:** 7.4 (HIGH) | **Open Issues:** 7 | **Connects To:** Robert-cargocats-frontgateservice

Robert-cargocats-aiservice is a Java Spring Boot backend that appears to expose AI/chat functionality to Robert-cargocats-frontgateservice, acting as an internal microservice that wraps LLM calls behind a REST API. Its name and connection graph suggest it's a dedicated AI service tier within a larger 'cargocats' application, sitting behind a gateway rather than facing the internet directly.

**Risk Rationale:** The model is a small, self-hosted model (smollm2:135m-tuned) served via a local Ollama instance (http://ollama:11434/v1), not an external cloud provider. Since the endpoint stays inside the environment, there's no data egress to a third party, which substantially lowers governance risk even though the endpoint is called through an OpenAI-compatible client.

**Recommendation:** Confirm the ollama host is on an internal-only network with no external exposure, and add basic usage monitoring/logging on the /openai endpoint so that if this ever gets pointed at an external provider it's caught by governance review.

#### AI Usage

| Attribute | Value |
|-----------|-------|
| **Model** | `smollm2:135m-tuned` |
| **Provider** | openai |
| **Endpoint** | `http://ollama:11434/v1` |
| **Host Category** | local |
| **Route** | unknown |
| **Frequency (model-wide)** | Very Low (2 invocations across all apps using this model) |
| **Reachability (this app)** | 1 code path(s) in this application |

**What it's doing:** AiController.openai receives the request and delegates to AiService.chat, which calls the OpenAI-compatible ChatCompletionService.create client against a local Ollama server. This produces a chat completion response for the front gateway service, likely generating a reply for an end-user or upstream request routed through the gateway.

---

### Robert-cargocats-reportservice

**Risk Level:** LOW

**Language:** JAVA | **Posture Score:** 6.7 (MEDIUM) | **Open Issues:** 2 | **Connects To:** Robert-cargocats-frontgateservice

Robert-cargocats-reportservice is a Java-based Tomcat servlet application that appears to generate logistics reports for the CargoCats system, connected to a front gateway service that likely routes client requests to it. Its servlet-based structure (InsightServlet, LogisticsInsightService) suggests it produces analytical or insight-driven reporting on logistics data rather than handling raw transactional traffic itself.

**Risk Rationale:** The model is served via a local Ollama instance (http://ollama:11434/v1) using the OpenAI-compatible client, meaning no data leaves the internal network to a third-party provider. This is self-hosted inference, so there's no external data egress concern, though it's worth confirming the model and endpoint are intentionally deployed rather than a developer default left in place.

**Recommendation:** Confirm that the Ollama deployment is an intentionally provisioned internal service (not a leftover dev/test container) and document it in the AI governance inventory. Add monitoring for prompt/response content if logistics data passed to LogisticsInsightService includes sensitive shipment, customer, or partner details.

#### AI Usage

| Attribute | Value |
|-----------|-------|
| **Model** | `smollm2:135m-tuned` |
| **Provider** | openai |
| **Endpoint** | `http://ollama:11434/v1` |
| **Host Category** | local |
| **Route** | unknown |
| **Frequency (model-wide)** | Very Low (2 invocations across all apps using this model) |
| **Reachability (this app)** | 1 code path(s) in this application |

**What it's doing:** InsightServlet.doPost handles an incoming POST request and calls LogisticsInsightService.getInsight, which invokes the OpenAI-compatible ChatCompletionService.create client against a local Ollama endpoint. This generates an AI-derived insight or summary for logistics report data as part of the report service's POST endpoint.

---

## Appendix: Methodology

AI/LLM usage data collected via Contrast Security runtime instrumentation. Application descriptions and connection data are derived from the Contrast architecture graph (application, server, and library relationships); AI usage descriptions are inferred from the real stack trace captured at each call site.

- **CRITICAL**: Likely sensitive/regulated data sent to an unvetted third-party model
- **HIGH**: Production cloud AI usage without an apparent governance process
- **MEDIUM**: Approved-looking usage lacking monitoring, or non-production usage that could reach production
- **LOW**: Local/self-hosted usage or clearly low-sensitivity usage
- **NOT_AI_RISK_ISSUE**: Benign, well-governed usage with no identifiable risk signal

---

*Report generated by Contrast AI Advisor*
*Powered by Contrast Security Runtime Observability*
