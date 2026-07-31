// Motor determinístico de CWE-22 (path traversal), portado do vulnscan_cli.py.
// Regra: nenhum achado aqui depende de "opinião" de IA. É regex + checagem
// de grounding (relê o texto original na linha exata antes de aceitar).
// Serve como EVIDÊNCIA VERIFICADA que é injetada no prompt da IA — a IA
// não pode contradizer um achado confirmado aqui sem justificar por quê.

export interface DeterministicFinding {
  line: number;
  snippet: string;
  language: 'python' | 'go' | 'javascript';
  guardPatternElsewhereInFile: number[]; // linhas onde um padrão de guarda aparece em QUALQUER lugar do arquivo (não prova nada sozinho, mas sinaliza pra IA ir conferir)
}

const PY_JOIN = /os\.path\.join\(/;
const PY_SINK = /\b(open|send_file|send_from_directory)\s*\(/;
const PY_GUARD = /os\.path\.(realpath|abspath|commonpath)|\.startswith\(/;

const GO_JOIN = /filepath\.Join\(/;
const GO_GUARD = /filepath\.Clean|strings\.HasPrefix|PathWithinBase|mount\.PathWithinBase/;

const JS_JOIN = /path\.join\(/;
const JS_SINK = /\b(fs\.readFile\w*|fs\.createReadStream|res\.sendFile)\s*\(/;
const JS_GUARD = /path\.normalize|\.startsWith\(/;

function findGuardLinesInWholeFile(lines: string[], guardRe: RegExp): number[] {
  const out: number[] = [];
  lines.forEach((l, i) => {
    if (guardRe.test(l)) out.push(i + 1);
  });
  return out;
}

function scanGeneric(
  lines: string[],
  joinRe: RegExp,
  sinkRe: RegExp,
  guardRe: RegExp,
  needsSink: boolean,
  language: DeterministicFinding['language'],
  guardWindowSize: number
): DeterministicFinding[] {
  const findings: DeterministicFinding[] = [];
  const guardLinesWholeFile = findGuardLinesInWholeFile(lines, guardRe);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!joinRe.test(line)) continue;
    const windowEnd = Math.min(lines.length, i + guardWindowSize);
    const window = lines.slice(i, windowEnd).join('\n');
    if (needsSink && !sinkRe.test(window)) continue;
    if (guardRe.test(window)) continue; // guarda BEM perto -> não vale nem reportar como candidato
    findings.push({
      line: i + 1,
      snippet: line.trim(),
      language,
      // guarda pode existir longe (ex: numa função chamada) — não decide
      // nada sozinho, só avisa a IA pra ir conferir antes de confirmar.
      guardPatternElsewhereInFile: guardLinesWholeFile.filter((l) => l < i + 1 || l > windowEnd),
    });
  }
  return findings;
}

/**
 * Roda a checagem determinística sobre um texto (pode ser 1 arquivo ou
 * vários concatenados com cabeçalhos "// ===== path ====="). Devolve só
 * achados que passaram no grounding check (a linha realmente existe e bate).
 */
export function scanForCWE22(fullText: string): DeterministicFinding[] {
  const lines = fullText.split('\n');
  const results: DeterministicFinding[] = [
    ...scanGeneric(lines, PY_JOIN, PY_SINK, PY_GUARD, true, 'python', 7),
    // Go: quando a função só retorna o Join direto (padrão do relatório
    // original do Kubernetes), a ausência de guarda JÁ é o achado — mas
    // ampliamos a janela pra 12 linhas pra dar chance de ver uma chamada
    // pra outra função de validação (ex: doSafeMakeDir) logo abaixo.
    ...scanGeneric(lines, GO_JOIN, GO_JOIN, GO_GUARD, false, 'go', 12),
    ...scanGeneric(lines, JS_JOIN, JS_SINK, JS_GUARD, true, 'javascript', 7),
  ];

  // Grounding check: relê a linha exata do texto original antes de aceitar.
  return results.filter((f) => {
    const actualLine = lines[f.line - 1];
    return actualLine !== undefined && actualLine.trim() === f.snippet;
  });
}

export function formatFindingsForPrompt(findings: DeterministicFinding[]): string {
  if (findings.length === 0) {
    return 'ANÁLISE ESTÁTICA DETERMINÍSTICA (regex, não-IA): nenhum padrão de join()-sem-guarda-próxima foi encontrado no código fornecido.';
  }
  const lines = findings.map((f) => {
    const warn = f.guardPatternElsewhereInFile.length > 0
      ? ` ⚠ ATENÇÃO: este arquivo também contém padrão(ões) de guarda de segurança na(s) linha(s) ${f.guardPatternElsewhereInFile.join(', ')} — pode ser que essa validação se aplique a este caminho através de uma função chamada. Você DEVE ler essas linhas antes de decidir.`
      : ' (nenhum padrão de guarda encontrado em nenhum lugar deste arquivo)';
    return `  - Linha ${f.line} (${f.language}): ${f.snippet}${warn}`;
  });
  return [
    'ANÁLISE ESTÁTICA DETERMINÍSTICA (regex, não-IA) — achados brutos, SEM considerar validação em outras funções:',
    ...lines,
    'REGRA: estes são apenas candidatos por padrão de texto. Regex não entende chamada de função. Se houver aviso de guarda em outra linha, você É OBRIGADO a ler essa linha no código fornecido e confirmar se ela protege este caminho antes de dizer "confirmado". Sem isso, marque "inconclusivo".',
  ].join('\n');
}
