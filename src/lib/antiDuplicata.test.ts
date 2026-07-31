import {
  makeFingerprint, classify, scoreCandidate, analyzeOriginality,
  FindingInput, OriginalityCandidate,
} from './antiDuplicata';

let pass = 0, fail = 0;
function ok(name: string, cond: boolean, extra = '') {
  if (cond) { pass++; console.log('  ✓', name); }
  else { fail++; console.log('  ✗', name, extra); }
}

// --- Achado realista: path traversal via subPath no Kubernetes (CWE-22) ---
const finding: FindingInput = {
  cwe: 'CWE-22',
  tipo: 'Path Traversal',
  arquivos: ['pkg/volume/util/subpath/subpath_linux.go'],
  funcoes: ['doSafeMakeDir', 'filepath.Join', 'PathWithinBase'],
  padrao_exploracao: 'symlink subPath escapes the volume base directory via ../',
  mensagens_erro: [],
  stack_trace: '',
  patch_sugerido: 'validate that the resolved path stays within base using filepath.Clean and HasPrefix',
  descricao: 'A subpath volume mount can be used to access files outside of the volume via a symlink, escaping the container filesystem boundary in kubernetes kubelet.',
  linguagem: 'go',
};

// --- Candidato que É a mesma classe (deve dar similaridade alta) ---
const cveMatch: OriginalityCandidate = {
  id: 'CVE-2021-25741',
  source: 'NVD',
  title: 'Kubernetes subpath volume mount symlink path traversal',
  description: 'A user may be able to create a container with subPath volume mounts to access files outside of the volume using a symlink, allowing path traversal in kubelet.',
  url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-25741',
  cwe: ['CWE-22'],
  published: '2021-09-16',
  commits: ['https://github.com/kubernetes/kubernetes/commit/abc123'],
  patch_url: 'https://github.com/kubernetes/kubernetes/pull/104796',
  references: [],
};

// --- Candidato irrelevante (deve dar similaridade baixa) ---
const cveNoise: OriginalityCandidate = {
  id: 'CVE-2019-11253',
  source: 'NVD',
  title: 'Kubernetes YAML parsing billion laughs denial of service',
  description: 'The Kubernetes API server allowed a YAML/JSON bomb causing resource exhaustion and denial of service.',
  url: 'https://nvd.nist.gov/vuln/detail/CVE-2019-11253',
  cwe: ['CWE-776'],
  published: '2019-10-16',
  commits: [],
  patch_url: null,
  references: [],
};

console.log('\n[1] Fingerprint estável e determinístico');
const fp1 = makeFingerprint(finding);
const fp2 = makeFingerprint({ ...finding, funcoes: [...finding.funcoes].reverse() }); // ordem não importa
ok('fingerprint tem 16 chars hex', /^[0-9a-f]{16}$/.test(fp1), fp1);
ok('fingerprint é estável (independe da ordem das funções)', fp1 === fp2, `${fp1} vs ${fp2}`);
const fpDiff = makeFingerprint({ ...finding, cwe: 'CWE-79' });
ok('fingerprint muda quando a CWE muda', fp1 !== fpDiff);

console.log('\n[2] Similaridade: match real >> ruído');
const s1 = scoreCandidate(finding, cveMatch);
const s2 = scoreCandidate(finding, cveNoise);
console.log(`    match: ${(s1.similarity*100).toFixed(0)}%  breakdown=`, s1.breakdown);
console.log(`    noise: ${(s2.similarity*100).toFixed(0)}%  breakdown=`, s2.breakdown);
ok('match tem CWE batida (cwe=1)', s1.breakdown.cwe === 1);
ok('ruído tem CWE diferente (cwe=0)', s2.breakdown.cwe === 0);
ok('match > ruído', s1.similarity > s2.similarity);
ok('match é forte (>0.6)', s1.similarity > 0.6, String(s1.similarity));
ok('ruído é fraco (<0.4)', s2.similarity < 0.4, String(s2.similarity));

console.log('\n[3] Classificação por faixa');
ok('95% -> 🔴 alta', classify(95).indicator === '🔴' && classify(95).label === 'alta');
ok('75% -> 🟡 media', classify(75).indicator === '🟡' && classify(75).label === 'media');
ok('40% -> 🟢 nenhuma', classify(40).indicator === '🟢' && classify(40).label === 'nenhuma');
ok('limite 90 é 🟡 (não passa de 90)', classify(90).label === 'media');
ok('limite 60 é 🟡', classify(60).label === 'media');
ok('59 é 🟢', classify(59).label === 'nenhuma');

console.log('\n[4] Orquestrador: análise completa');
const analysis = analyzeOriginality(finding, [cveNoise, cveMatch], ['NVD','GHSA','OSV']);
ok('escolheu o melhor candidato (CVE-2021-25741)', analysis.best_match?.id === 'CVE-2021-25741');
ok('ordenou por similaridade (best é o primeiro)', analysis.candidates[0].id === 'CVE-2021-25741');
ok('nunca afirma "é duplicata" no texto', !/é duplicata|is a duplicate/i.test(analysis.justificativa));
ok('tem fingerprint', /^[0-9a-f]{16}$/.test(analysis.fingerprint));
ok('lista fontes consultadas', analysis.sources_consulted.length === 3);
console.log(`    score=${analysis.score}% label=${analysis.label} ${analysis.indicator} confiança=${analysis.confidence}`);
console.log(`    alerta: ${analysis.alert ? 'SIM' : 'não'}`);

console.log('\n[5] Caso sem candidatos -> 🟢 e nenhum alerta');
const empty = analyzeOriginality(finding, [], ['NVD','GHSA']);
ok('score 0 quando não há candidatos', empty.score === 0);
ok('label nenhuma', empty.label === 'nenhuma');
ok('sem alerta', empty.alert === null);
ok('best_match null', empty.best_match === null);

console.log(`\n==== ${pass} passaram, ${fail} falharam ====\n`);
if (fail > 0) process.exit(1);
