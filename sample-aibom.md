<!-- Contrast AI Advisor Report -->

# Contrast AI Advisor
## Inventory of AI-Enabled Applications

---

**Client:** Contrast AI Usage Inventory
**Report Date:** August 31, 2026
**Assessment Type:** Runtime AI/LLM Usage Inventory & Governance Risk Assessment

---

## Executive Summary

> This is not a self-reported inventory. Every application and AI usage instance in this report was **actually observed running** by Contrast Security's runtime instrumentation - including the model, provider, destination endpoint, and the real call stack behind each usage.

- **2** application(s) with observed AI usage
- **2** distinct AI usage instance(s) across those applications
- No applications flagged CRITICAL or HIGH risk

| Risk Level | Applications |
|------------|--------------|
| LOW | 2 |

---

## Application Inventory

### Robert-cargocats-aiservice

**Risk Level:** LOW

**Language:** JAVA | **Posture Score:** 7.4 (HIGH) | **Open Issues:** 7 | **Connects To:** Robert-cargocats-frontgateservice

Robert-cargocats-aiservice is a Java Spring Boot backend that exposes AI/chat functionality to the Robert-cargocats-frontgateservice, acting as a dedicated internal microservice for handling AI-related requests within the CargoCats application. It sits behind a gateway rather than being directly internet-facing, consistent with a service-oriented architecture where AI logic is isolated from the main API layer.

**Risk Rationale:** The model is routed to a self-hosted Ollama instance (http://ollama:11434/v1) rather than a third-party cloud provider, so no data leaves the organization's infrastructure. The model itself (a small, likely internally fine-tuned smollm2 variant) further suggests a controlled, self-managed deployment rather than shadow use of an external SaaS LLM.

**Recommendation:** Confirm the Ollama host is properly network-isolated and that the smollm2:135m-tuned model and its fine-tuning data are documented/inventoried, then continue monitoring for any future addition of cloud-based providers to this service.

#### AI Usage

**Model:** `smollm2:135m-tuned` (openai)

| Attribute | Value |
|-----------|-------|
| **Endpoint** | `http://ollama:11434/v1` |
| **Host Category** | local |
| **Route** | unknown |
| **Frequency** | Very Low (2 invocations) |
| **Reachability** | 2 code path(s) |

**What it's doing:** AiController.openai receives the request and delegates to AiService.chat, which calls the OpenAI-compatible ChatCompletionService.create client method. This client is configured to point at a local Ollama endpoint rather than OpenAI's cloud API, so the call generates a chat completion response using a self-hosted, fine-tuned small model.

**Stack Trace:**
```
com.openai.services.blocking.chat.ChatCompletionServiceImpl$WithRawResponseImpl.create(ChatCompletionServiceImpl.kt)
com.openai.services.blocking.chat.ChatCompletionServiceImpl.create(ChatCompletionServiceImpl.kt:63)
com.openai.services.blocking.chat.ChatCompletionService.create(ChatCompletionService.kt:64)
com.contrast.aiservice.AiService.chat(AiService.java:54)
com.contrast.aiservice.AiController.openai(AiController.java:30)
java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native
Method)
java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke(Unknown
Source)
java.base/jdk.internal.reflect.DelegatingMethodAccessorImpl.invoke(Unknown
Source)
java.base/java.lang.reflect.Method.invoke(Unknown
Source)
org.springframework.web.method.support.InvocableHandlerMethod.doInvoke(InvocableHandlerMethod.java:258)
org.springframework.web.method.support.InvocableHandlerMethod.invokeForRequest(InvocableHandlerMethod.java:191)
org.springframework.web.servlet.mvc.method.annotation.ServletInvocableHandlerMethod.invokeAndHandle(ServletInvocableHandlerMethod.java:118)
org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter.invokeHandlerMethod(RequestMappingHandlerAdapter.java:986)
org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter.handleInternal(RequestMappingHandlerAdapter.java:891)
org.springframework.web.servlet.mvc.method.AbstractHandlerMethodAdapter.handle(AbstractHandlerMethodAdapter.java:87)
org.springframework.web.servlet.DispatcherServlet.doDispatch(DispatcherServlet.java:1089)
org.springframework.web.servlet.DispatcherServlet.doService(DispatcherServlet.java:979)
org.springframework.web.servlet.FrameworkServlet.processRequest(FrameworkServlet.java:1014)
org.springframework.web.servlet.FrameworkServlet.doGet(FrameworkServlet.java:903)
jakarta.servlet.http.HttpServlet.service(HttpServlet.java:564)
org.springframework.web.servlet.FrameworkServlet.service(FrameworkServlet.java:885)
jakarta.servlet.http.HttpServlet.service(HttpServlet.java:658)
org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:195)
org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:140)
org.apache.tomcat.websocket.server.WsFilter.doFilter(WsFilter.java:51)
org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:164)
org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:140)
org.springframework.web.filter.RequestContextFilter.doFilterInternal(RequestContextFilter.java:100)
org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:116)
org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:164)
org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:140)
org.springframework.web.filter.FormContentFilter.doFilterInternal(FormContentFilter.java:93)
org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:116)
org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:164)
org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:140)
org.springframework.web.filter.ServerHttpObservationFilter.doFilterInternal(ServerHttpObservationFilter.java:114)
org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:116)
org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:164)
org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:140)
org.springframework.web.filter.CharacterEncodingFilter.doFilterInternal(CharacterEncodingFilter.java:201)
org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:116)
org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:164)
org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:140)
org.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:167)
org.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:90)
org.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:483)
org.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:116)
org.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:93)
org.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:74)
org.apache.catalina.valves.RemoteIpValve.invoke(RemoteIpValve.java:732)
org.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:344)
org.apache.coyote.http11.Http11Processor.service(Http11Processor.java:398)
org.apache.coyote.AbstractProcessorLight.process(AbstractProcessorLight.java:63)
org.apache.coyote.AbstractProtocol$ConnectionHandler.process(AbstractProtocol.java:903)
org.apache.tomcat.util.net.NioEndpoint$SocketProcessor.doRun(NioEndpoint.java:1740)
org.apache.tomcat.util.net.SocketProcessorBase.run(SocketProcessorBase.java:52)
org.apache.tomcat.util.threads.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1189)
org.apache.tomcat.util.threads.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:658)
org.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:63)
java.base/java.lang.Thread.run(Unknown
Source)
```

---

### Robert-cargocats-reportservice

**Risk Level:** LOW

**Language:** JAVA | **Posture Score:** 6.7 (MEDIUM) | **Open Issues:** 2 | **Connects To:** Robert-cargocats-frontgateservice

Robert-cargocats-reportservice is a Java servlet-based backend that generates reports for the CargoCats system, likely producing logistics or shipment insights consumed by the front gate service. It sits behind Robert-cargocats-frontgateservice and exposes servlet endpoints such as InsightServlet for report/insight generation.

**Risk Rationale:** The model runs locally via Ollama rather than a third-party cloud provider, so no data egress to an external vendor occurs. Risk is limited to whatever logistics data is included in the prompt, but since inference stays within the organization's own infrastructure, exposure is minimal.

**Recommendation:** Confirm the Ollama instance is only reachable on internal network segments and not exposed externally, and document this usage in the AI inventory even though it's self-hosted, so future changes (e.g., swapping to a cloud model) get proper review.

#### AI Usage

**Model:** `smollm2:135m-tuned` (openai)

| Attribute | Value |
|-----------|-------|
| **Endpoint** | `http://ollama:11434/v1` |
| **Host Category** | local |
| **Route** | unknown |
| **Frequency** | Very Low (2 invocations) |
| **Reachability** | 2 code path(s) |

**What it's doing:** InsightServlet.doPost calls LogisticsInsightService.getInsight, which invokes the OpenAI-compatible ChatCompletionService.create client pointed at a local Ollama endpoint. This generates a logistics insight or summary in response to a POST request, likely producing narrative text for a report.

**Stack Trace:**
```
com.openai.services.blocking.chat.ChatCompletionServiceImpl$WithRawResponseImpl.create(ChatCompletionServiceImpl.kt)
com.openai.services.blocking.chat.ChatCompletionServiceImpl.create(ChatCompletionServiceImpl.kt:63)
com.openai.services.blocking.chat.ChatCompletionService.create(ChatCompletionService.kt:64)
com.contrast.reportservice.LogisticsInsightService.getInsight(LogisticsInsightService.java:62)
com.contrast.reportservice.InsightServlet.doPost(InsightServlet.java:36)
javax.servlet.http.HttpServlet.service(HttpServlet.java:555)
javax.servlet.http.HttpServlet.service(HttpServlet.java:623)
org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:201)
org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:146)
org.apache.tomcat.websocket.server.WsFilter.doFilter(WsFilter.java:57)
org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:170)
org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:146)
org.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:166)
org.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:88)
org.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:534)
org.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:129)
org.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:86)
org.apache.catalina.valves.AbstractAccessLogValve.invoke(AbstractAccessLogValve.java:764)
org.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:71)
org.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:350)
org.apache.coyote.http11.Http11Processor.service(Http11Processor.java:407)
org.apache.coyote.AbstractProcessorLight.process(AbstractProcessorLight.java:71)
org.apache.coyote.AbstractProtocol$ConnectionHandler.process(AbstractProtocol.java:1344)
org.apache.tomcat.util.net.NioEndpoint$SocketProcessor.doRun(NioEndpoint.java:2089)
org.apache.tomcat.util.net.SocketProcessorBase.run(SocketProcessorBase.java:74)
org.apache.tomcat.util.threads.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:976)
org.apache.tomcat.util.threads.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:494)
org.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:80)
java.base/java.lang.Thread.run(Thread.java:840)
```

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