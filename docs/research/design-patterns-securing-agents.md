# Design Patterns for Securing LLM Agents - Research Analysis

## Paper Summary

**Full Title:** Design Patterns for Securing LLM Agents against Prompt Injections  
**Authors:** Beat Buesser (IBM), Ana-Maria Creţu (EPFL), Edoardo Debenedetti (ETH Zurich), Daniel Dobos (Swisscom), Daniel Fabian (Google), Marc Fischer (Invariant Labs), David Froelicher (Swisscom), Kathrin Grosse (IBM), Daniel Naeff (ETH AI Center), Ezinwanne Ozoani (AppliedAI Institute for Europe), Andrew Paverd (Microsoft), Florian Tramèr (ETH Zurich), Václav Volhejn (Kyutai)  
**Date:** June 2025 (arXiv:2506.08837v1)  
**URL:** https://arxiv.org/html/2506.08837v1

### Key Contribution

This paper presents **six principled design patterns** for building LLM agents with **provable resistance to prompt injection attacks**. The authors argue that general-purpose agents cannot provide meaningful security guarantees, and instead propose constrained agent designs that trade some utility for security.

### Core Design Patterns

The paper presents six main patterns, all following a common principle: **once an LLM agent has ingested untrusted input, it must be constrained so that input cannot trigger consequential actions**.

#### 1. Action-Selector Pattern
- **Description:** Agent acts as an LLM-modulated "switch" that selects from predefined actions
- **Security:** Immune to prompt injections - no feedback from actions back to agent
- **Trade-off:** Limited utility, loses fuzzy search capabilities

#### 2. Plan-Then-Execute Pattern  
- **Description:** Agent commits to a fixed action plan before processing untrusted data
- **Security:** Provides "control flow integrity" - untrusted data cannot change the plan
- **Limitation:** Can still manipulate action parameters, doesn't prevent user prompt injections

#### 3. LLM Map-Reduce Pattern
- **Description:** Dispatch isolated sub-agents to process individual pieces of untrusted data, aggregate safely
- **Security:** Strict isolation prevents injection spread between data pieces
- **Implementation:** Two approaches - non-LLM reduce operation or constrained LLM reduce with safety checks

#### 4. Dual LLM Pattern
- **Description:** Separate privileged LLM (tools, no untrusted data) from quarantined LLM (no tools, processes untrusted data)
- **Security:** Symbolic variable handling prevents direct injection feedback
- **Architecture:** Requires orchestrator component for safe variable dereferencing

#### 5. Code-Then-Execute Pattern
- **Description:** Agent writes formal program code to solve task, then executes it
- **Security:** Explicit program structure limits attack surface
- **Generalization:** Extends plan-then-execute with formal programming constructs

#### 6. Context-Minimization Pattern
- **Description:** Remove user prompt from context after action determination
- **Security:** Prevents prompt injections from affecting response generation
- **Application:** Particularly useful for customer service scenarios

### 10 Case Studies

The paper includes comprehensive case studies demonstrating real-world applicability:

1. **OS Assistant with Fuzzy Search** - File operations with untrusted file contents
2. **SQL Agent** - Database queries with potential data contamination  
3. **Email and Calendar Assistant** - Third-party email processing
4. **Customer Service Chatbot** - User prompt injection prevention
5. **Booking Assistant** - Third-party service provider data
6. **Recruitment Agent** - CV processing with injection risks
7. **Healthcare Assistant** - Patient data privacy concerns
8. **Software Engineering Agent** - Code repository analysis
9. **Research Assistant** - Academic paper processing
10. **Financial Analysis Agent** - Market data with potential manipulation

### Provability Claims and Threat Models

**Provability Approach:**
- Patterns provide **formal guarantees** under specific constraints
- Security holds **even if underlying LLM is vulnerable** to prompt injection
- Focus on **system-level isolation** rather than model-level defenses

**Threat Models:**
- **Indirect Prompt Injection:** Attacker controls third-party data processed by agent
- **Direct Prompt Injection:** Malicious or inadvertent user input
- **Data Exfiltration:** Unauthorized information extraction
- **Unauthorized Actions:** Tool misuse, privilege escalation
- **Denial of Service:** Resource exhaustion attacks

## Feature Delta with LLMTrace

### Architectural Layer Analysis

**LLMTrace operates at the proxy/transport layer:**
- HTTP/WebSocket request/response interception
- Token-level analysis and rate limiting
- Request routing and authentication
- Protocol-agnostic monitoring

**These patterns operate at the application/agent layer:**
- LLM workflow orchestration
- Tool access control and sandboxing
- Context management and isolation
- Agent reasoning and planning

### Pattern Applicability Analysis

| Pattern | Description | LLMTrace Applicability | Gap |
|---------|-------------|----------------------|-----|
| **Action-Selector** | Predefined action selection | **HIGH** - Can enforce action allowlists at proxy level | Need action pattern detection |
| **Plan-Then-Execute** | Fixed action planning | **MEDIUM** - Can detect plan deviations in request patterns | Cannot enforce planning phase |
| **LLM Map-Reduce** | Isolated sub-agent processing | **LOW** - Limited visibility into agent orchestration | No sub-agent tracking |
| **Dual LLM** | Privileged/quarantined separation | **MEDIUM** - Can route to different endpoints based on data trust | Need trust level classification |
| **Code-Then-Execute** | Formal program generation | **LOW** - Code execution happens post-proxy | Cannot inspect generated code |
| **Context-Minimization** | Context cleanup | **HIGH** - Can strip context in request modification | Need context analysis capabilities |

### Existing Capability Mapping

**Current LLMTrace features that align with patterns:**

1. **Rate Limiting as Action Gating:**
   - Maps to Action-Selector pattern constraint mechanism
   - Can prevent rapid-fire unauthorized actions
   - Could be enhanced with action-type awareness

2. **Request/Response Filtering:**
   - Supports Context-Minimization through content stripping
   - Can implement basic prompt injection detection
   - Potential for pattern-aware filtering

3. **Multi-Model Routing:**
   - Enables Dual LLM pattern through endpoint separation
   - Can route trusted/untrusted requests to different models
   - Supports isolation boundaries

4. **Authentication and Authorization:**
   - Enforces tool access constraints (Action-Selector support)
   - Can implement privilege separation
   - Maps to agent capability restrictions

## Actionable Recommendations

### Immediate Enhancements

1. **Pattern-Aware Request Classification:**
   ```
   - Add request metadata for agent pattern identification
   - Implement pattern-specific validation rules
   - Create pattern compliance scoring
   ```

2. **Enhanced Action Detection:**
   ```
   - Extend tool calling detection to support action allowlists
   - Add pattern matching for common agent action sequences
   - Implement action-type based rate limiting
   ```

3. **Context Manipulation Features:**
   ```
   - Add context stripping/minimization capabilities
   - Implement sensitive data redaction in requests
   - Support for context isolation enforcement
   ```

### Medium-term Development

4. **Agent Pattern Compliance Monitoring:**
   ```
   - Detect when agents violate declared patterns
   - Alert on suspicious action sequence deviations  
   - Provide pattern adherence metrics
   ```

5. **Trust-Based Routing:**
   ```
   - Implement data source trust classification
   - Route untrusted data processing to quarantined endpoints
   - Support for symbolic variable handling
   ```

6. **Advanced Prompt Injection Detection:**
   ```
   - Pattern-specific injection detection algorithms
   - Integration with agent workflow understanding
   - Behavioral anomaly detection for pattern violations
   ```

### Research Questions for LLMTrace

**High Priority:**
- Can we enforce Action-Selector patterns through proxy-level allowlisting?
- How can we detect Plan-Then-Execute pattern violations in request streams?
- What agent pattern compliance metrics would be most valuable?

**Medium Priority:**
- Can LLMTrace help implement Context-Minimization automatically?
- How can we support Dual LLM routing with trust-level classification?
- What behavioral signatures indicate agent pattern adherence?

**Long-term:**
- Should LLMTrace provide a pattern-compliance-as-a-service layer?
- Can we build an agent security pattern recommendation engine?
- How can we integrate with agent frameworks to enforce patterns automatically?

### Implementation Priorities

1. **Phase 1 (1-2 months):** Action-Selector pattern support through enhanced allowlisting
2. **Phase 2 (2-4 months):** Context-Minimization features and pattern detection
3. **Phase 3 (4-6 months):** Full pattern compliance monitoring and trust-based routing
4. **Phase 4 (6+ months):** Advanced behavioral analysis and pattern recommendation

### Strategic Value Proposition

**For LLMTrace:** 
- Positions as the security layer for agent pattern enforcement
- Differentiates from basic prompt injection detection
- Creates integration opportunities with agent frameworks

**For Users:**
- Provides systematic agent security implementation guidance  
- Reduces agent security implementation complexity
- Offers measurable security compliance metrics

This research demonstrates that **agent-level security patterns can be significantly enhanced by proxy-level enforcement**, creating a compelling integration opportunity for LLMTrace in the emerging agent security ecosystem.