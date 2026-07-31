// =====================================================================
// Módulo Anti-Duplicata — núcleo de lógica (100% offline / testável).
//
// O que ESTE arquivo faz (sem rede):
//   1. Extrai as características de um achado.
//   2. Gera uma assinatura (fingerprint) estável.
//   3. Compara semanticamente o achado com candidatos vindos das fontes
//      públicas (CVE/NVD, GHSA, OSV, etc.) — que são coletados no backend.
//   4. Calcula uma pontuação de similaridade 0..1.
//   5. Classifica em 🔴 / 🟡 / 🟢.
//
// O que ESTE arquivo NÃO faz: buscar na internet. Isso é responsabilidade
// do coletor no servidor (server_anti_duplicata.mjs), porque o navegador
// esbarra em CORS e não tem como rodar Scrapy. Aqui só entra o resultado
// já coletado, para pontuar de forma determinística.
//
// REGRA DE OURO: nunca afirmar automaticamente que é duplicata. Isto é
// triagem para o pesquisador humano decidir — nada mais.
// =====================================================================

// ---------------------------------------------------------------------
// Tipos de entrada/saída (também exportados em ../types para o app).
// ---------------------------------------------------------------------

export interface FindingInput {
  cwe: string | null;            // ex: "CWE-22"
  tipo: string | null;           // ex: "Path Traversal"
  arquivos: string[];            // arquivos afetados
  funcoes: string[];             // funções envolvidas (sink/source/guards)
  padrao_exploracao: string;     // como se explora (payload, vetor)
  mensagens_erro: string[];      // mensagens de erro observadas
  stack_trace: string;           // stack trace, quando existir
  patch_sugerido: string;        // patch/remediação sugerida
  descricao: string;             // texto livre do achado (evidência/justificativa)
  linguagem?: string;            // python | go | javascript | ...
}

export interface OriginalityCandidate {
  id: string;                    // ex: "CVE-2021-25741" ou "GHSA-xxxx"
  source: string;                // "NVD" | "GHSA" | "OSV" | "ProjectZero" | ...
  title: string;
  description: string;
  url: string;
  cwe: string[];                 // CWEs associadas (pode ter mais de uma)
  published: string | null;      // data ISO da divulgação
  commits: string[];             // links/hashes de commits relacionados
  patch_url: string | null;      // link do patch, quando houver
  references: string[];          // links extras (advisories, blogs)
}

export interface ScoredCandidate extends OriginalityCandidate {
  similarity: number;            // 0..1
  breakdown: {                   // de onde veio a pontuação (transparência)
    cwe: number;
    texto: number;
    funcoes: number;
    arquivos: number;
    patch: number;
  };
  matched_terms: string[];       // termos que bateram (evidência)
}

export type OriginalityLabel = 'alta' | 'media' | 'nenhuma';
export type OriginalityConfidence = 'Alta' | 'Média' | 'Baixa';

export interface OriginalityAnalysis {
  fingerprint: string;           // assinatura do achado
  features: FindingInput;        // características extraídas (para o relatório)
  score: number;                 // 0..100 (similaridade do melhor candidato)
  label: OriginalityLabel;       // alta | media | nenhuma
  indicator: '🔴' | '🟡' | '🟢';
  confidence: OriginalityConfidence;
  best_match: ScoredCandidate | null;
  candidates: ScoredCandidate[]; // top-N ordenados por similaridade
  sources_consulted: string[];   // quais fontes foram consultadas
  alert: string | null;          // alerta se similaridade alta
  justificativa: string;         // por que caiu nessa classificação
}

// ---------------------------------------------------------------------
// 1. Normalização e tokenização
// ---------------------------------------------------------------------

const STOPWORDS = new Set([
  'a','o','e','de','da','do','em','um','uma','para','com','por','que','no','na',
  'the','a','an','of','to','in','on','and','or','is','are','be','this','that',
  'via','when','with','from','can','may','could','it','its','as','at','if',
]);

export function normalize(s: string): string {
  return (s || '')
    .toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '') // tira acentos
    .replace(/[^a-z0-9./_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

export function tokenize(s: string): string[] {
  return normalize(s)
    .split(' ')
    .filter((t) => t.length >= 3 && !STOPWORDS.has(t));
}

function tokenSet(s: string): Set<string> {
  return new Set(tokenize(s));
}

// Jaccard entre dois conjuntos de tokens (0..1).
function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 || b.size === 0) return 0;
  let inter = 0;
  for (const t of a) if (b.has(t)) inter++;
  return inter / (a.size + b.size - inter);
}

// Overlap: quantos tokens de A aparecem em B, sobre o tamanho de A.
// Útil quando A (o achado) é curto e B (o CVE) é longo.
function overlap(a: Set<string>, b: Set<string>): number {
  if (a.size === 0) return 0;
  let inter = 0;
  for (const t of a) if (b.has(t)) inter++;
  return inter / a.size;
}

// Similaridade textual robusta: pega a MELHOR entre jaccard e as duas
// sobreposições direcionais. Justificativa: descrições de CVE/advisory têm
// tamanhos bem diferentes do texto do achado; a métrica direcional "quanto
// do menor está contido no maior" captura duplicata melhor que jaccard puro.
function textSimilarity(a: Set<string>, b: Set<string>): number {
  return Math.max(jaccard(a, b), overlap(a, b), overlap(b, a));
}

// ---------------------------------------------------------------------
// 2. Fingerprint estável (FNV-1a de 64 bits, hex de 16 chars).
//    Determinístico: mesmo achado -> mesma assinatura, sempre.
// ---------------------------------------------------------------------

function fnv1a(str: string): string {
  // FNV-1a 64-bit usando BigInt (estável entre execuções e plataformas).
  const FNV_OFFSET = 0xcbf29ce484222325n;
  const FNV_PRIME = 0x100000001b3n;
  const MASK = 0xffffffffffffffffn;
  let hash = FNV_OFFSET;
  for (let i = 0; i < str.length; i++) {
    hash ^= BigInt(str.charCodeAt(i));
    hash = (hash * FNV_PRIME) & MASK;
  }
  return hash.toString(16).padStart(16, '0');
}

// A assinatura é feita das características ESTÁVEIS do achado (não do
// texto solto, que varia). Ordena tudo para não depender da ordem.
export function makeFingerprint(f: FindingInput): string {
  const parts = [
    'cwe:' + normalize(f.cwe || 'none'),
    'tipo:' + normalize(f.tipo || 'none'),
    'lang:' + normalize(f.linguagem || 'none'),
    'files:' + f.arquivos.map((x) => normalize(basename(x))).sort().join(','),
    'funcs:' + f.funcoes.map(normalize).sort().join(','),
    'sinks:' + extractSinkTokens(f).sort().join(','),
  ];
  return fnv1a(parts.join('|'));
}

function basename(p: string): string {
  const clean = (p || '').split(/[?#]/)[0];
  const parts = clean.split(/[/\\]/);
  return parts[parts.length - 1] || clean;
}

// Tenta pegar os "sinks" clássicos citados no padrão de exploração/funções.
const SINK_HINTS = [
  'open','readfile','read_file','sendfile','send_file','send_from_directory',
  'createreadstream','filepath.join','os.path.join','path.join','fs.readfile',
  'exec','eval','system','query','deserialize','pickle.loads','yaml.load',
];
function extractSinkTokens(f: FindingInput): string[] {
  const hay = normalize([f.padrao_exploracao, f.funcoes.join(' '), f.descricao].join(' '));
  return SINK_HINTS.filter((h) => hay.includes(h));
}

// ---------------------------------------------------------------------
// 3. Similaridade achado <-> candidato (0..1) com breakdown transparente.
//
//    Modelo: dois sinais SEMPRE disponíveis formam a base, e os sinais de
//    nível de código entram como BÔNUS aditivo (não como peso que zera).
//    Motivo: descrições do NVD são prosa e raramente citam nomes de função
//    ou arquivo — se esses sinais fossem 30% do peso fixo, todo match real
//    contra o NVD ficaria artificialmente baixo. Com o modelo aditivo:
//      - CWE igual + descrição semelhante já leva ao 🟡 alto;
//      - só chega ao 🔴 (>90%) quando há CORROBORAÇÃO de código (função,
//        arquivo ou patch batendo — o que vem de GHSA/OSV/commits), que é
//        justamente quando a confiança de duplicata é maior.
//
//    base   = 0.45*CWE + 0.45*texto
//    bônus  = 0.10 * melhor sinal de código (func | arquivo | patch)
// ---------------------------------------------------------------------

const W = { cwe: 0.45, texto: 0.45, codigo: 0.10 };

export function scoreCandidate(f: FindingInput, c: OriginalityCandidate): ScoredCandidate {
  const findingCwe = normalize(f.cwe || '');
  const cweScore =
    findingCwe && c.cwe.some((x) => normalize(x) === findingCwe) ? 1 : 0;

  const findingText = tokenSet([f.tipo, f.descricao, f.padrao_exploracao, f.mensagens_erro.join(' ')].join(' '));
  const candText = tokenSet([c.title, c.description].join(' '));
  const textoScore = textSimilarity(findingText, candText);

  // Sinais de nível de código — casam melhor contra fontes ricas (GHSA, OSV,
  // commits, patch), que trazem identificadores de código, não só prosa.
  const candCode = tokenSet([c.title, c.description, c.patch_url || '', c.commits.join(' '), c.references.join(' ')].join(' '));

  const findingFuncs = new Set([
    ...f.funcoes.map((x) => normalize(basename(x))),
    ...extractSinkTokens(f),
  ].filter(Boolean));
  const funcScore = overlap(findingFuncs, candCode);

  const findingFiles = new Set(f.arquivos.map((x) => normalize(basename(x))).filter(Boolean));
  const fileScore = overlap(findingFiles, candCode);

  const patchScore =
    f.patch_sugerido && (c.patch_url || c.commits.length)
      ? overlap(tokenSet(f.patch_sugerido), tokenSet([c.patch_url || '', c.commits.join(' '), c.description].join(' ')))
      : 0;

  const codeScore = Math.max(funcScore, fileScore, patchScore);

  const breakdown = {
    cwe: cweScore,
    texto: textoScore,
    funcoes: funcScore,
    arquivos: fileScore,
    patch: patchScore,
  };

  const similarity =
    W.cwe * cweScore +
    W.texto * textoScore +
    W.codigo * codeScore;

  // termos que bateram (evidência p/ o relatório)
  const matched: string[] = [];
  for (const t of findingText) if (candText.has(t)) matched.push(t);

  return {
    ...c,
    similarity: Math.min(1, Math.round(similarity * 1000) / 1000),
    breakdown,
    matched_terms: Array.from(new Set(matched)).slice(0, 20),
  };
}

// ---------------------------------------------------------------------
// 4. Classificação (indicador visual) + confiança.
//    🔴 > 90% | 🟡 60–90% | 🟢 < 60%
// ---------------------------------------------------------------------

export function classify(scorePercent: number): {
  label: OriginalityLabel;
  indicator: '🔴' | '🟡' | '🟢';
} {
  if (scorePercent > 90) return { label: 'alta', indicator: '🔴' };
  if (scorePercent >= 60) return { label: 'media', indicator: '🟡' };
  return { label: 'nenhuma', indicator: '🟢' };
}

// Confiança leva em conta quão forte o melhor bateu E se há vários
// candidatos concordando (ou um único isolado). CWE batido dá segurança.
function computeConfidence(best: ScoredCandidate | null, all: ScoredCandidate[]): OriginalityConfidence {
  if (!best) return 'Baixa';
  const cweHit = best.breakdown.cwe === 1;
  const strong = all.filter((c) => c.similarity >= 0.6).length;
  if (best.similarity >= 0.9 && cweHit) return 'Alta';
  if (best.similarity >= 0.75 && (cweHit || strong >= 2)) return 'Alta';
  if (best.similarity >= 0.6) return 'Média';
  return 'Baixa';
}

// ---------------------------------------------------------------------
// 5. Orquestrador: recebe achado + candidatos e devolve a análise completa.
// ---------------------------------------------------------------------

export function analyzeOriginality(
  finding: FindingInput,
  candidates: OriginalityCandidate[],
  sourcesConsulted: string[],
  topN = 5
): OriginalityAnalysis {
  const fingerprint = makeFingerprint(finding);

  const scored = candidates
    .map((c) => scoreCandidate(finding, c))
    .sort((a, b) => b.similarity - a.similarity)
    .slice(0, topN);

  const best = scored[0] || null;
  const scorePercent = best ? Math.round(best.similarity * 100) : 0;
  const { label, indicator } = classify(scorePercent);
  const confidence = computeConfidence(best, scored);

  const alert =
    label === 'alta'
      ? '⚠️ ALTA probabilidade de duplicata. Revise CUIDADOSAMENTE as fontes abaixo ANTES de enviar o relatório. A decisão final é sua — a ferramenta NÃO afirma que é duplicata.'
      : null;

  const justificativa = buildJustificativa(label, best, scorePercent, sourcesConsulted);

  return {
    fingerprint,
    features: finding,
    score: scorePercent,
    label,
    indicator,
    confidence,
    best_match: best,
    candidates: scored,
    sources_consulted: sourcesConsulted,
    alert,
    justificativa,
  };
}

function buildJustificativa(
  label: OriginalityLabel,
  best: ScoredCandidate | null,
  scorePercent: number,
  sources: string[]
): string {
  if (!best || label === 'nenhuma') {
    return `Nenhuma correspondência pública relevante encontrada (melhor similaridade ${scorePercent}%, abaixo de 60%) após consultar ${sources.length} fonte(s): ${sources.join(', ')}. Isso NÃO garante ineditismo — apenas que não achamos divulgação óbvia. Vale uma busca manual antes de concluir.`;
  }
  const b = best.breakdown;
  const drivers: string[] = [];
  if (b.cwe === 1) drivers.push('mesma CWE');
  if (b.texto >= 0.4) drivers.push('descrição muito parecida');
  if (b.funcoes >= 0.4) drivers.push('funções/sinks em comum');
  if (b.arquivos >= 0.4) drivers.push('arquivos coincidentes');
  if (b.patch >= 0.4) drivers.push('patch semelhante');
  const why = drivers.length ? drivers.join(', ') : 'sobreposição parcial de termos';
  return `Melhor correspondência: ${best.id} (${best.source}), similaridade ${scorePercent}%. Fatores: ${why}. Consultadas ${sources.length} fonte(s): ${sources.join(', ')}. Classificação para TRIAGEM humana — a ferramenta não declara duplicata automaticamente.`;
}

// ---------------------------------------------------------------------
// Wrapper de front: chama o coletor no backend (/api/anti-duplicata) para
// pegar os candidatos das fontes públicas e roda a pontuação localmente.
// Mantém a coleta (rede) no servidor e a decisão (transparente) no cliente.
// ---------------------------------------------------------------------
export async function runAntiDuplicata(finding: FindingInput): Promise<OriginalityAnalysis> {
  const resp = await fetch('/api/anti-duplicata', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ finding }),
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data?.error || `coletor retornou ${resp.status}`);
  const candidates: OriginalityCandidate[] = data.candidates || [];
  const sources: string[] = data.sources_consulted || [];
  return analyzeOriginality(finding, candidates, sources);
}

// ---------------------------------------------------------------------
// Helper: monta um FindingInput a partir do formato de vulnerabilidade
// usado no relatório (vulnerability_chain[]) OU do AnalysisResult.
// ---------------------------------------------------------------------

export function findingFromReportVuln(v: any): FindingInput {
  const vec = v.execution_vector || {};
  const remed = vec.patch_remediation || {};
  return {
    cwe: v.cwe_id || v.cwe || null,
    tipo: v.vulnerability_type || v.tipo || null,
    arquivos: [remed.target_file, vec.target_file, ...(v.arquivos || [])].filter(Boolean),
    funcoes: [v.source, v.sink, vec.input_field, ...(v.funcoes || [])].filter(Boolean),
    padrao_exploracao: [vec.payload, v.padrao_exploracao, v.modelagem_ataque].filter(Boolean).join(' | '),
    mensagens_erro: [vec.exception_raised, ...(v.mensagens_erro || [])].filter(Boolean),
    stack_trace: v.stack_trace || '',
    patch_sugerido: remed.validation_logic || v.patch_sugerido || '',
    descricao: [v.justificativa, v.evidencia, v.relatorio_markdown].filter(Boolean).join(' ').slice(0, 4000),
    linguagem: v.language || v.linguagem || undefined,
  };
}
