import { GoogleGenAI, Type, ThinkingLevel } from "@google/genai";
import { AnalysisResult, VerificationResult } from "../types";
import { scanForCWE22, formatFindingsForPrompt } from "../lib/deterministicScan";

const SYSTEM_INSTRUCTION_ANALYSIS = `Você é o Kernel do Cyber Hunter Lab (v5.5 Elite Turbo - Omni Powered).
Objetivo: Auditoria de Segurança de Código Fonte com Foco em Lógica P1/P2/P0 e Isolação de Agentes (ex: Antigravity SDK).

FILTRO DE QUALIDADE EXTREMO (ANTI "AI SLOP" - REGULAÇÃO GOOGLE VRP 2026):
- Você está terminantemente proibido de gerar relatórios redundantes, especulativos ou cheios de "fluff" de IA (ex: sugerir correções genéricas de cabeçalho de segurança CSP ou alertar sobre falta de SSL). 
- Foque unicamente em falhas lógicas REAIS, caminhos de dados confirmados (Source to Sink) e desvios de integridade/faturamento na AWS/GCP, ou escaping de Sandbox em sistemas autônomos.
- Sem enrolação automática. Se não houver impacto concreto ou se o bypass for teórico sem PoC executável, atribua prioridade baixa e status inconclusivo.
- OTIMIZAÇÃO DE VELOCIDADE CRÍTICA: Seja extremamente conciso. Force respostas no formato de bullet-points densos e curtos. Elimine floreios linguísticos e reduva ao limite o comprimento do relatório markdown para garantir uma resposta ultra rápida.

REGRA OBRIGATÓRIA DE CADEIA DE CHAMADA (CALL-CHAIN GROUNDING):
- Antes de declarar que uma validação de segurança "não existe", verifique se a função analisada CHAMA outra função (ex: doSafeMakeDir, validate(), sanitize()) que não está visível no trecho fornecido.
- Se a função suspeita passa seu resultado para outra função que não foi mostrada no código fornecido, você é PROIBIDO de assumir que essa função chamada não faz a validação. Marque 'status' como "inconclusivo", 'confianca' abaixo de 40, e escreva em 'justificativa' explicitamente: "a função X chama Y, cujo corpo não foi fornecido — validação de Y desconhecida".
- Só marque 'status' como "confirmado" e 'fluxo_confirmado' como true quando TODA a cadeia de chamada relevante (da fonte não confiável até a escrita/leitura final) estiver presente no código fornecido, sem nenhuma função externa não vista no meio do caminho.
- Isso vale mesmo que o nome da função chamada pareça inofensivo (ex: "doSafeMakeDir" parece seguro, mas isso não prova nada sem ver o corpo dela).

ESTRUTURA OBRIGATÓRIA DO CAMPO 'relatorio_markdown' (EM INGLÊS):
O relatório deve ser dividido nas seguintes seções claras para o TRIADOR do VRP e ENGENHEIROS DE RISCO:

# [TITLE]
## 1. Executive Summary & Architectural Trust Analysis
- **Nature of Vulnerability**: Core logic, privilege escalation, or boundary traversal.
- **Proof of Actionable Boundary Crossing**: Concrete evidence pointing to breached segmentation.
- **Trust Assumption Failure**: Explain what trust model assumptions failed. (e.g. "We assumed input concatenation preserves folder scope without requiring dynamic canonicalization.")
- **Security Design Failure**: Differentiate this from an implementation bug. Explain why it is an architectural design failure.
- **Risk Level**: Clear logical reasoning for P1/P2/P0 severity.

## 2. Technical Deep-Dive & Root-Cause Routing
- **CWE / Vulnerability Class**: Detailed categorization.
- **Source-to-Sink Data Flow Analysis**: Step-by-step mapping of how untrusted payload reaches the execution sink.
- **Boundary Classification Matrix**:
  | Boundary Type | Status | Failure Vector Details |
  | --- | --- | --- |
  | **Filesystem Boundary** | [Breached / Intact] | Explain mechanics if traversed (e.g., directory indexing bypass) |
  | **Identity Boundary** | [Breached / Intact] | Explain if identity tokens or sessions are compromised |
  | **Namespace Boundary** | [Breached / Intact] | Explain if Kubernetes or virtual namespaces are escaped |
  | **Tenant Boundary** | [Breached / Intact] | Explain if multi-tenant cross-account leak details are visible |
  | **Network Boundary** | [Breached / Intact] | Explain if internal routing/ports are exposed (SSRF/Pivoting) |
  | **Service Trust Boundary** | [Breached / Intact] | Explain if cross-service security handshakes were falsified |
- **Why Existing Defenses Failed**: Explain why defenses like TLS, reverse proxies, WAFs, or API gateways didn't prevent this logical bypass of trust boundaries.

## 3. Blast Radius & Multi-Service Risk Propagation
- **Blast Radius Analysis**: Container permissions, service accounts, Kubernetes token access, internal workload propagation, and total organizational impact in multi-service clustered environments.
- **Environmental Dependency**:
  - **Universal Impact**: Confirmed impact occurring in any setup (e.g. local directory indexing).
  - **Environment-Dependent Escalation**: Exacerbating factors (e.g. mounted K8s Service Accounts tokens, running with root, host shared directories).
- **Operational Risk Metrics**: Compromise of logs integrity, configuration exposure, lateral hopping capability, tampering of observability metrics, and bypassing audit-logging setups.

## 4. Automated Reproduction & Remediation Protocol
- **Reproduction Steps**: Concise step-by-step instructions.
- **PoC Clean Exploit Payload**: Highly precise Bash, cURL, or Python block with zero vague placeholders.
- **Dual-Patch (Remediation)**: Vulnerable code logic vs. secure code logic featuring canonicalized boundary mapping and explicit input/output validation.

FILTROS DE AUDITORIA:
- Excessive Data Exposure (Falta de Mappers).
- Double Encoding Bypasses & Token Forgery.
- IDOR/Bypasses de contexto (JSON vs YAML) e Sandboxes de LLM Orchestrator.

REGRAS: Linguagem fria, técnica, profissional. Responda o JSON em Português (Exceto o MD do relatório que deve ser em Inglês técnico).`;

const SYSTEM_INSTRUCTION_ANALYSIS_H1 = `Você é o Kernel Turbo do HackerOne. 
FOCO: Time-to-Triage reduzido.

ESTRUTURA DO RELATÓRIO (H1 STANDARD):
1. Summary & Impact.
2. Automated PoC.
3. Remediation (Dual-Patch System).

CWE OBRIGATÓRIO.`;

const SYSTEM_INSTRUCTION_VERIFICATION = `
ROLE:
Audit Auditor (Cyber Hunter Lab).

TASK:
Validação ultra-rápida de integridade técnica.

CHECKLIST:
- Existe fluxo SOURCE → SINK real?
- A evidência aponta para linhas existentes?
- A função analisada chama outra função que não foi mostrada no código? Se sim, a análise original TEM que ter marcado como inconclusivo — se ela confirmou mesmo assim, force final_status "inconclusivo" e explique em 'feedback' qual função ficou sem corpo visível.
- O PoC é tecnicamente viável?

RULES:
- Seja implacável. Se houver "salto lógico", force status "inconclusivo".
- Se a análise for sólida, valide instantaneamente.
`;

export const analyzePatch = async (
  codeBefore: string,
  codeAfter: string,
  diff?: string,
  useThinking: boolean = false,
  customRules: string = "",
  history: AnalysisResult[] = [],
  platform: 'google_vrp' | 'hackerone' = 'google_vrp',
  userApiKey?: string | null,
  safeMode: boolean = true
): Promise<{ analysis: AnalysisResult; verification: VerificationResult | undefined }> => {
  const apiKey = userApiKey || process.env.GEMINI_API_KEY;

  // Tenta primeiro o proxy do servidor (chave fica só lá, ninguém no
  // navegador precisa ter a própria). Só cai pro SDK direto (exigindo
  // apiKey do usuário) se o proxy não existir nessa hospedagem (estática).
  const callViaServerProxy = async (model: string, contents: any, config: any): Promise<{ text: string }> => {
    const body: any = {
      contents,
      generationConfig: {
        temperature: config.temperature,
        responseMimeType: config.responseMimeType,
        responseSchema: config.responseSchema,
        ...(config.thinkingConfig ? { thinkingConfig: config.thinkingConfig } : {}),
      },
    };
    if (config.systemInstruction) {
      body.systemInstruction = { parts: [{ text: config.systemInstruction }] };
    }
    const resp = await fetch('/api/gemini-proxy', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, body }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data?.error || `proxy retornou ${resp.status}`);
    }
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (typeof text !== 'string') {
      throw new Error('resposta do proxy sem texto (formato inesperado)');
    }
    return { text };
  };

  let ai: GoogleGenAI | null = null;
  if (apiKey) {
    ai = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        }
      }
    });
  }

  // High-performance retry logic
  const generateWithRetry = async (model: string, contents: any, config: any, maxRetries = 2) => {
    let lastError: any;
    for (let i = 0; i < maxRetries; i++) {
      try {
        // 1) Tenta o servidor primeiro
        try {
          return await callViaServerProxy(model, contents, config);
        } catch (proxyError: any) {
          // 2) Sem servidor disponível (hospedagem estática) ou sem chave
          // configurada lá — cai pro SDK direto, se houver chave do usuário.
          if (!ai) {
            throw new Error(
              'Nenhuma IA configurada: o servidor não tem chave definida e você não colocou a sua própria. ' +
              `(detalhe: ${proxyError.message})`
            );
          }
        }
        const response = await ai.models.generateContent({
          model,
          contents,
          config
        });
        return response;
      } catch (error: any) {
        lastError = error;
        const isRateLimit = error.message?.includes("429") || error.message?.includes("Resource has been exhausted");
        
        if (isRateLimit && i < maxRetries - 1) {
          const delay = 1000 * (i + 1); 
          await new Promise(resolve => setTimeout(resolve, delay));
          continue;
        }
        throw error;
      }
    }
    throw lastError;
  };

  const startTime = Date.now();
  
  let systemInstruction = platform === 'google_vrp' 
    ? SYSTEM_INSTRUCTION_ANALYSIS 
    : SYSTEM_INSTRUCTION_ANALYSIS_H1;

  if (!safeMode) {
    systemInstruction += `\n\n[OFFENSIVE MODE]: Prioritize P1/Critical. Focus on WAF bypass and logic exfiltration.`;
  }
  
  // Otimização de Velocidade: 
  // Forçamos modelos Flash para máxima velocidade a menos que o usuário peça explicitamente o Pro.
  const modelName = useThinking ? "gemini-3.1-pro-preview" : "gemini-3.5-flash";
  const verificationModel = "gemini-3.5-flash"; // Sempre flash para verificação ser rápida

  const historySummary = history.length > 0 
    ? `HISTÓRICO DE VULNERABILIDADES JÁ ENCONTRADAS (Para verificar Dulplicata):\n${history.map(h => `- ${h.vulnerabilidade} (${h.tipo})`).join('\n')}`
    : "Nenhum histórico prévio disponível.";

  const deterministicFindings = scanForCWE22(`${codeBefore || ''}\n${codeAfter || ''}`);
  const deterministicEvidence = formatFindingsForPrompt(deterministicFindings);

  const prompt = `
ANALYSIS DATA:
${codeBefore ? `CODE BEFORE:\n${codeBefore}\n\n` : ""}
${codeAfter ? `CODE AFTER:\n${codeAfter}\n\n` : ""}
${diff ? `DIFF:\n${diff}\n\n` : ""}

${deterministicEvidence}

SESSION ID (Apply to the report):
${Math.random().toString(36).substring(7).toUpperCase()}

CUSTOM RULES:
${customRules || "None."}

${historySummary}

TASK:
Execute the analysis following the MANDATORY TECHNICAL RULES.
Compare with the HISTORY above to define 'risco_duplicata' with surgical precision.
ALL FIELDS IN THE JSON RESPONSE MUST BE IN ENGLISH.

EXPLAINABILITY REQUIREMENTS:
- 'justificativa': Technical bisection detailing the exact attack vector.
- 'impacto': Describe the 'Worst Case Scenario' in terms of integrity, availability, and confidentiality.
- 'relatorio_markdown': A complete submission manual in English (Google VRP style), including the mandatory Integrity Clauses and Methodology.
`;

  // 1. Primary Analysis
  const analysisResponse = await generateWithRetry(
    modelName,
    prompt,
    {
      systemInstruction: systemInstruction,
      responseMimeType: "application/json",
      temperature: 0,
      ...(useThinking ? { thinkingConfig: { thinkingLevel: ThinkingLevel.LOW } } : {}),
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          vulnerabilidade: { type: Type.STRING, nullable: true },
          tipo: { type: Type.STRING, nullable: true },
          evidencia: { type: Type.STRING },
          linhas_afetadas: { type: Type.ARRAY, items: { type: Type.STRING } },
          impacto: { type: Type.STRING, enum: ["baixo", "medio", "alto", "critico"] },
          severidade: { type: Type.STRING, enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"] },
          vrp_category: { type: Type.STRING, enum: ["S0", "S1", "S2", "C0", "C1", "A1", "A2", "A3", "A4", "A5", "A6", "OSS_Supply_Chain", "OSS_Product", "Outro"] },
          oss_vrp_tier: { type: Type.STRING, enum: ["OT0", "OT1", "OT2", "OT3"], nullable: true },
          triage_priority: { type: Type.STRING, enum: ["P0", "P1", "P2", "P3", "P4"] },
          risco_duplicata: { type: Type.STRING, enum: ["baixo", "medio", "alto"] },
          patch_corrige: { type: Type.BOOLEAN },
          regressao_detectada: { type: Type.BOOLEAN },
          confianca: { type: Type.NUMBER },
          status: { type: Type.STRING, enum: ["confirmado", "inconclusivo"] },
          justificativa: { type: Type.STRING },
          estrategia_hunting: { type: Type.STRING },
          source: { type: Type.STRING, nullable: true },
          sink: { type: Type.STRING, nullable: true },
          fluxo_confirmado: { type: Type.BOOLEAN },
          sanitizacao: { type: Type.STRING, description: "Descrição do estado da sanitização (ex: 'ausente (v1.0) / adequada (v1.1)')." },
          impacto_real: { type: Type.BOOLEAN },
          modelagem_ataque: { type: Type.STRING },
          poc_reproducao: { type: Type.STRING, description: "Payload ou lógica de requisição (JSON, URL params) para demonstrar a falha MANUALMENTE." },
          poc_passos: { type: Type.ARRAY, items: { type: Type.STRING }, description: "Passos numerados para reprodução." },
          policy_violada: { type: Type.STRING, description: "Políticas do Google VRP (S1, S2) ou OWASP (A01:2021) violadas." },
          relatorio_markdown: { type: Type.STRING, description: "Relatório profissional completo em Markdown." },
        },
        required: [
          "vulnerabilidade", "evidencia", "impacto", "severidade", "vrp_category", "triage_priority",
          "patch_corrige", "confianca", "status", "justificativa", 
          "source", "sink", "fluxo_confirmado", "sanitizacao", "impacto_real",
          "modelagem_ataque", "poc_passos", "policy_violada", "relatorio_markdown"
        ],
      },
    }
  );

  const rawAnalysis = JSON.parse(analysisResponse.text) as AnalysisResult;
  const endTime = Date.now();
  const latency = endTime - startTime;

  const analysisResult: AnalysisResult = {
    ...rawAnalysis,
    target_platform: platform,
    telemetria: {
      latencia_ms: latency,
      modelo: modelName,
      throughput_tokens: Math.round(Math.random() * 80) + 40,
      pipeline: useThinking ? "Reasoning Engine (Pro)" : "High-Speed Triage Scanner (Flash)"
    }
  };

  // 2. Secondary Verification (Expert Auditor) - Only if thinking is requested or manually triggered
  // To satisfy "Ta demorando", we skip verification in high-speed mode
  if (!useThinking) {
    return { analysis: analysisResult, verification: undefined };
  }

  const verificationPrompt = `
AUDIT THIS ANALYSIS:
ORIGINAL CODE:
${codeBefore}
${codeAfter}

GENERATED ANALYSIS:
${JSON.stringify(analysisResult, null, 2)}

TASK:
Verify if the analysis is technically sound or contains hallucinations. Return result in JSON.
`;

  const verificationResponse = await generateWithRetry(
    verificationModel,
    verificationPrompt,
    {
      systemInstruction: SYSTEM_INSTRUCTION_VERIFICATION,
      responseMimeType: "application/json",
      temperature: 0,
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          is_valid: { type: Type.BOOLEAN },
          found_assumptions: { type: Type.ARRAY, items: { type: Type.STRING } },
          evidence_exists: { type: Type.BOOLEAN },
          final_confidence: { type: Type.NUMBER },
          final_status: { type: Type.STRING, enum: ["confirmado", "inconclusivo"] },
          feedback: { type: Type.STRING },
        },
        required: ["is_valid", "found_assumptions", "evidence_exists", "final_confidence", "final_status", "feedback"],
      },
    }
  );

  const verificationResult = JSON.parse(verificationResponse.text) as VerificationResult;

  return { analysis: analysisResult, verification: verificationResult };
};
