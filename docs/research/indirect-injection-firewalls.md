# Research Analysis: Indirect Prompt Injections - Are Firewalls All You Need?

**Date:** February 1, 2025  
**Paper:** "Indirect Prompt Injections: Are Firewalls All You Need?" (arXiv:2510.05244v1)  
**Authors:** Rishika Bhagwatkar, Kevin Kasa, Abhay Puri, Gabriel Huang, Irina Rish, Graham W. Taylor, Krishnamurthy Dj Dvijotham, Alexandre Lacoste  
**Affiliation:** ServiceNow Research, Mila, Université de Montréal, Vector Institute, University of Guelph  

---

## Paper Summary

### Core Concept

The paper introduces a **simple, modular, and model-agnostic defense** for tool-calling LLM agents based on two firewalls operating at the agent-tool boundary:

1. **Tool-Input Firewall (Minimizer)** — Filters sensitive information from tool call arguments before execution
2. **Tool-Output Firewall (Sanitizer)** — Removes malicious content from tool responses before returning to the agent

This "minimize & sanitize" approach requires **no LLM retraining** and can be deployed out-of-the-box.

### Key Architecture

```
User Task → Agent → [Minimizer] → Tool → [Sanitizer] → Agent Response
```

**Algorithm Flow:**
1. Agent generates tool call with input arguments
2. **Minimize Phase:** Filter sensitive data from input arguments using context of user task and tool description
3. **Tool Execution:** Execute tool with filtered inputs
4. **Sanitize Phase:** Remove malicious outputs using knowledge of user task and input arguments
5. Return sanitized output to agent

### Evaluation & Results

**Benchmarks Tested:**
- **AgentDojo:** 949 security evaluations across banking, slack, travel, workspace domains
- **Agent Security Bench (ASB):** 400 evaluations with two-stage tool selection
- **InjecAgent:** Simulated tool calls with basic/enhanced injection attacks  
- **Tau-Bench:** Augmented with data stealing attacks via DoomArena framework

**Key Results:**
- **0% Attack Success Rate (ASR)** across all benchmarks with minimal utility degradation
- **Sanitizer alone** achieved optimal security-utility tradeoff
- **Combined approach** (Minimizer + Sanitizer) showed slightly lower utility due to aggressive input redaction
- Outperformed complex defenses like CaMeL and Melon while maintaining higher utility

### Critical Benchmark Limitations Identified

The paper exposed significant flaws in existing security benchmarks:

1. **AgentDojo Issues:**
   - Injection vectors overwrite task-critical content making tasks unsolvable
   - Brittle utility metrics that mis-score semantic success
   - Fixed evaluation improved utility by 18%

2. **Agent Security Bench Issues:**
   - Forced injection of "attack-tools" inflates ASR artificially  
   - ASR dropped from 70% → 9.25% when attack-tools weren't force-injected
   - Poor utility evaluation ignoring task sequence requirements

3. **InjecAgent Issues:**
   - No utility metrics provided
   - Overly simplistic attack patterns

### Defense Limitations

Despite strong benchmark performance, the authors demonstrated successful bypass using **Braille encoding** to defeat the GPT-4o-based Sanitizer, highlighting the need for stronger, more diverse attack strategies in future benchmarks.

---

## Feature Delta with LLMTrace

LLMTrace operates as a **transparent proxy** (WAF-like architecture) providing real-time security analysis, while the paper's firewalls operate at **tool boundaries** within agent workflows.

### Architecture Comparison

| Feature | Paper Approach | LLMTrace | Gap Analysis |
|---------|---------------|----------|-------------|
| **Deployment Model** | Tool-boundary firewalls within agent | Transparent proxy between app and LLM | Different intervention points |
| **Security Scope** | Tool input/output filtering | Request/response analysis + streaming | LLMTrace broader but different focus |
| **Input Minimization** | ✅ Tool-Input Firewall removes unnecessary PII/data | ❌ No input minimization beyond PII detection | **Gap: Input minimization** |
| **Output Sanitization** | ✅ Tool-Output Firewall removes injection content | ✅ Response analysis but not contextual sanitization | **Gap: Contextual output filtering** |
| **Tool Context Awareness** | ✅ Uses user task + tool description for decisions | ❌ No tool-specific analysis | **Gap: Tool-aware security** |
| **Real-time Analysis** | ❌ Synchronous blocking firewalls | ✅ Asynchronous non-blocking analysis | LLMTrace advantage |
| **Indirect Injection Focus** | ✅ Specifically designed for tool-based injection | ⚠️ General prompt injection detection | **Gap: Tool-specific injection patterns** |
| **Multi-turn Context** | ❌ Per-tool-call analysis | ✅ Session-aware threat tracking | LLMTrace advantage |
| **Streaming Support** | ❌ Batch processing | ✅ Token-by-token analysis | LLMTrace advantage |

### Current LLMTrace Security Features

**✅ Strengths:**
- **Comprehensive Pattern Detection:** RegexSecurityAnalyzer with 40+ injection patterns
- **PII Detection & Redaction:** International PII patterns with checksum validation
- **ML-based Analysis:** DeBERTa models for sophisticated attack detection
- **Streaming Security:** Real-time token-level analysis during SSE streams
- **Behavioral Analysis:** Statistical anomaly detection and cost monitoring
- **Agent Action Analysis:** Command execution, file access, web request monitoring

**❌ Current Limitations vs Paper:**
- **No Input Minimization:** LLMTrace doesn't filter request arguments before forwarding
- **No Tool Context:** Doesn't understand tool purposes or legitimate data requirements
- **No Output Sanitization:** Detects but doesn't actively filter tool response content
- **Limited Tool-Boundary Analysis:** Operates at HTTP proxy level, not tool execution level

### Specific Indirect Prompt Injection Handling

**LLMTrace Current Approach:**
```rust
// From llmtrace-security/src/lib.rs
pub fn detect_injection_patterns(&self, text: &str) -> Vec<SecurityFinding> {
    // Pattern-based detection for various attack types
    let findings = self.injection_patterns.iter()
        .filter(|p| p.regex.is_match(text))
        .map(|p| SecurityFinding::new(...))
        .collect();
    
    // Base64 decoding detection
    findings.extend(self.detect_base64_injection(text));
    
    // Structural attacks (many-shot, repetition)
    findings.extend(self.detect_many_shot_attack(text));
    findings.extend(self.detect_repetition_attack(text));
    
    findings
}
```

**Paper's Approach:**
- **Contextual Analysis:** Firewall decisions based on user task + tool description + original arguments
- **Proactive Filtering:** Actually modifies content rather than just alerting
- **Tool-Specific Logic:** Different filtering strategies per tool type

---

## Actionable Recommendations

### 1. Implement Tool-Boundary Firewalling (High Priority)

**Recommendation:** Add tool-aware input minimization and output sanitization to LLMTrace's proxy-level analysis.

**Implementation Strategy:**
```yaml
# New configuration section for tool-boundary security
security:
  tool_boundary:
    enabled: true
    input_minimizer:
      enabled: true
      strategies:
        - remove_unnecessary_pii
        - context_aware_filtering
        - argument_validation
    output_sanitizer:
      enabled: true
      strategies:
        - instruction_removal
        - context_validation
        - content_filtering
```

**Technical Implementation:**
```rust
pub struct ToolBoundaryAnalyzer {
    minimizer: ToolInputFirewall,
    sanitizer: ToolOutputFirewall,
    tool_registry: Arc<ToolRegistry>,
}

impl ToolBoundaryAnalyzer {
    pub async fn analyze_tool_call(&self, request: &LLMRequest) -> Result<FilteredRequest> {
        // Extract tool calls from request
        let tool_calls = self.extract_tool_calls(request)?;
        
        for tool_call in &tool_calls {
            // Get tool context from registry
            let tool_context = self.tool_registry.get_tool_info(&tool_call.name).await?;
            
            // Apply input minimization
            let filtered_args = self.minimizer.filter_arguments(
                &tool_call.arguments,
                &request.user_task,
                &tool_context
            )?;
            
            tool_call.arguments = filtered_args;
        }
        
        Ok(FilteredRequest::new(request.clone(), tool_calls))
    }
    
    pub async fn sanitize_tool_response(
        &self, 
        response: &str, 
        tool_context: &ToolContext,
        user_task: &str
    ) -> Result<String> {
        self.sanitizer.sanitize_response(response, tool_context, user_task).await
    }
}
```

### 2. Add Context-Aware Input Minimization (Medium Priority)

**Approach:** Implement the paper's Tool-Input Firewall concept within LLMTrace's request processing pipeline.

**Key Features:**
- **PII Minimization:** Remove unnecessary personal data from tool arguments
- **Context Validation:** Ensure tool arguments align with stated user task
- **Argument Filtering:** Remove potentially dangerous or unnecessary parameters

**Implementation:**
```rust
pub struct ContextAwareMinimizer {
    pii_detector: Arc<PIIDetector>,
    context_analyzer: Arc<ContextAnalyzer>,
}

impl ContextAwareMinimizer {
    pub async fn minimize_tool_arguments(
        &self,
        arguments: &serde_json::Value,
        user_task: &str,
        tool_description: &str,
    ) -> Result<serde_json::Value> {
        let mut filtered_args = arguments.clone();
        
        // Remove unnecessary PII
        if let Some(pii_findings) = self.pii_detector.scan(&arguments.to_string()).await? {
            filtered_args = self.redact_unnecessary_pii(filtered_args, pii_findings, user_task)?;
        }
        
        // Context validation - remove arguments not relevant to user task
        filtered_args = self.context_analyzer.filter_irrelevant_args(
            filtered_args,
            user_task,
            tool_description
        )?;
        
        Ok(filtered_args)
    }
}
```

### 3. Enhance Tool Output Sanitization (High Priority)

**Approach:** Implement contextual output filtering that understands the user's original intent and tool's purpose.

**Features:**
- **Instruction Removal:** Strip potential injection commands from tool responses
- **Content Validation:** Ensure response aligns with user task
- **Metadata Filtering:** Remove system prompts or internal information

**Implementation:**
```rust
pub struct ContextualSanitizer {
    injection_detector: Arc<InjectionDetector>,
    content_validator: Arc<ContentValidator>,
}

impl ContextualSanitizer {
    pub async fn sanitize_tool_response(
        &self,
        response: &str,
        user_task: &str,
        tool_context: &ToolContext,
        original_args: &serde_json::Value,
    ) -> Result<String> {
        let mut sanitized = response.to_string();
        
        // Remove detected injection patterns
        let injection_findings = self.injection_detector.analyze(response).await?;
        for finding in injection_findings {
            sanitized = self.remove_injection_content(&sanitized, &finding)?;
        }
        
        // Validate content relevance to user task
        if !self.content_validator.is_relevant(&sanitized, user_task, tool_context)? {
            sanitized = self.filter_irrelevant_content(&sanitized, user_task)?;
        }
        
        // Remove potential system information leakage
        sanitized = self.remove_system_leakage(&sanitized)?;
        
        Ok(sanitized)
    }
}
```

### 4. Create Tool Registry and Classification System (Medium Priority)

**Rationale:** To implement tool-aware security, LLMTrace needs to understand different tool types and their security requirements.

**Schema:**
```rust
pub struct ToolDefinition {
    pub name: String,
    pub category: ToolCategory,
    pub security_level: SecurityLevel,
    pub required_permissions: Vec<Permission>,
    pub allowed_data_types: Vec<DataType>,
    pub output_constraints: OutputConstraints,
}

pub enum ToolCategory {
    WebBrowsing,
    CodeExecution,
    FileSystem,
    Database,
    Communication,
    DataProcessing,
}

pub struct SecurityLevel {
    pub risk_score: u8,  // 1-10
    pub requires_minimization: bool,
    pub requires_sanitization: bool,
    pub max_data_scope: DataScope,
}
```

### 5. Extend Streaming Analysis for Tool Responses (Low Priority)

**Approach:** Apply the paper's sanitization logic to streaming tool responses in real-time.

**Technical Challenge:** Tool responses in LLMTrace context are typically final HTTP responses, not streaming tool outputs. This would require deeper integration with agent frameworks.

### Priority Assessment

| Recommendation | Priority | Effort | Impact | Implementation Timeline |
|----------------|----------|--------|--------|----------------------|
| Tool-Boundary Firewalling | **High** | High | High | 6-8 weeks |
| Input Minimization | **Medium** | Medium | Medium | 4-6 weeks |
| Output Sanitization | **High** | Medium | High | 4-6 weeks |
| Tool Registry | **Medium** | Low | Medium | 2-3 weeks |
| Streaming Tool Analysis | **Low** | High | Low | 8-10 weeks |

### Integration with Existing LLMTrace Architecture

The paper's firewall approach is **highly applicable** to LLMTrace's proxy architecture:

**✅ Compatible Aspects:**
- Both systems analyze content for security threats
- Both can operate without model retraining
- Both support real-time analysis
- Both focus on practical deployment

**🔧 Adaptation Required:**
- LLMTrace operates at HTTP proxy level vs. tool execution level
- Need to parse and understand tool calls from LLM requests
- Must maintain transparent proxy behavior while adding filtering
- Integration with existing security analysis pipeline

**📈 Expected Benefits:**
- **Reduced False Positives:** Context-aware analysis vs. generic pattern matching
- **Proactive Defense:** Content filtering vs. passive detection
- **Tool-Specific Security:** Tailored defenses per tool category
- **Enhanced Coverage:** Address indirect prompt injection specifically

---

## Conclusion

The paper's "minimize & sanitize" approach represents a **significant advancement** in LLM agent security that is highly relevant to LLMTrace. While LLMTrace has strong foundational security capabilities, implementing tool-boundary firewalling would address key gaps in handling indirect prompt injections.

**Key Strategic Insights:**
1. **Contextual Analysis > Pattern Matching:** The paper's success shows that understanding user intent and tool purpose dramatically improves security effectiveness
2. **Proactive Filtering > Passive Detection:** Actually sanitizing content prevents attacks vs. just alerting on them
3. **Tool-Awareness Essential:** Different tools have different security requirements and attack surfaces

**Next Steps:**
1. Begin with **Tool Registry implementation** to establish foundation
2. Implement **Output Sanitization** for immediate security improvement  
3. Add **Input Minimization** for comprehensive tool-boundary protection
4. Develop **streaming integration** for real-time filtering
5. Create **custom benchmarks** that address the weaknesses identified in existing evaluation frameworks

This research reinforces that LLMTrace's transparent proxy approach is architecturally sound, but can be significantly enhanced by incorporating the paper's contextual, tool-aware security strategies.