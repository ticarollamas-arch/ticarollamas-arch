// =====================================================================
// Coletor Anti-Duplicata (backend) — "mecanismo de coleta" das fontes
// públicas. Roda no servidor (não no navegador) porque:
//   1. o navegador esbarra em CORS ao chamar NVD/GitHub direto;
//   2. Scrapy é Python e não roda dentro de um app React.
//
// Estratégia: usar APIs OFICIAIS onde existem (NVD, GitHub Advisories,
// OSV.dev) — muito mais confiáveis e estáveis que raspar HTML. Para as
// fontes que só têm HTML (HackerOne Hacktivity, Bugcrowd, blogs), há um
// spider Scrapy OPCIONAL em scrapy_collector/ (veja o README de lá); se o
// endpoint SCRAPY_COLLECTOR_URL estiver configurado, este coletor também
// consulta ele. Se não, ignora e segue com as APIs.
//
// Este arquivo NÃO pontua nem decide nada. Só COLETA e NORMALIZA
// candidatos. A pontuação/classificação é feita no front (antiDuplicata.ts),
// de forma determinística e transparente.
//
// IMPORTANTE: rede é necessária em runtime. Neste sandbox de dev a rede
// está bloqueada; no seu deploy (que já retorna resultado no terminal)
// funciona. Cada fonte é best-effort: se uma falhar, as outras seguem.
// =====================================================================

const DEFAULT_TIMEOUT_MS = 9000;

async function fetchJson(url, opts = {}, timeout = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeout);
  try {
    const r = await fetch(url, { ...opts, signal: controller.signal });
    const text = await r.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { /* não-JSON */ }
    return { ok: r.ok, status: r.status, data, text };
  } finally {
    clearTimeout(t);
  }
}

// Extrai os termos de busca mais úteis de um achado (sem stopwords).
const STOP = new Set(['the','a','an','of','to','in','on','and','or','is','are','be','via','with','from','can','may','could','it','its','as','at','if','that','this']);
function searchTerms(finding, max = 8) {
  const raw = [
    finding.tipo || '',
    finding.padrao_exploracao || '',
    (finding.arquivos || []).map(basename).join(' '),
    (finding.funcoes || []).join(' '),
    finding.descricao || '',
  ].join(' ').toLowerCase();
  const freq = {};
  for (const w of raw.replace(/[^a-z0-9._-]+/g, ' ').split(/\s+/)) {
    if (w.length >= 4 && !STOP.has(w)) freq[w] = (freq[w] || 0) + 1;
  }
  return Object.entries(freq).sort((a, b) => b[1] - a[1]).slice(0, max).map(([w]) => w);
}
function basename(p) {
  const parts = String(p || '').split(/[?#]/)[0].split(/[/\\]/);
  return parts[parts.length - 1] || String(p || '');
}
function normCwe(cwe) {
  if (!cwe) return null;
  const m = String(cwe).match(/CWE-\d+/i);
  return m ? m[0].toUpperCase() : null;
}

// ---------------------------------------------------------------------
// Fonte 1 — NVD CVE API 2.0 (free-text + filtro por CWE)
//   Docs: https://nvd.nist.gov/developers/vulnerabilities
//   Rate limit: 5 req/30s sem chave, 50 req/30s com chave (NVD_API_KEY).
// ---------------------------------------------------------------------
async function queryNVD(finding, apiKey) {
  const terms = searchTerms(finding, 6).join(' ');
  if (!terms.trim()) return { source: 'NVD', candidates: [], error: 'sem termos de busca' };
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(terms)}&resultsPerPage=15`;
  const headers = apiKey ? { apiKey } : {};
  const { ok, status, data, text } = await fetchJson(url, { headers }, 12000);
  if (!ok || !data) return { source: 'NVD', candidates: [], error: `NVD status ${status}: ${(text || '').slice(0, 120)}` };

  const candidates = (data.vulnerabilities || []).map((item) => {
    const cve = item.cve || {};
    const desc = (cve.descriptions || []).find((d) => d.lang === 'en')?.value || '';
    const cwes = [];
    for (const w of cve.weaknesses || []) for (const d of w.description || []) {
      const c = normCwe(d.value); if (c) cwes.push(c);
    }
    const refs = (cve.references || []).map((r) => r.url);
    const commits = refs.filter((u) => /\/commit\/|\/pull\/|\/commits\//.test(u));
    const patch = refs.find((u) => /\/pull\/|\/commit\/|patch|fix/i.test(u)) || null;
    return {
      id: cve.id, source: 'NVD', title: cve.id, description: desc,
      url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
      cwe: Array.from(new Set(cwes)), published: cve.published || null,
      commits, patch_url: patch, references: refs,
    };
  });
  return { source: 'NVD', candidates };
}

// ---------------------------------------------------------------------
// Fonte 2 — GitHub Security Advisories (GHSA), filtro por CWE
//   Docs: https://docs.github.com/rest/security-advisories/global-advisories
//   Sem token: rate limit baixo (~60/h). Com token (GITHUB_TOKEN): 5000/h.
// ---------------------------------------------------------------------
async function queryGHSA(finding, token) {
  const cwe = normCwe(finding.cwe);
  const params = new URLSearchParams({ per_page: '15', sort: 'published', direction: 'desc' });
  if (cwe) params.set('cwes', cwe);
  const url = `https://api.github.com/advisories?${params.toString()}`;
  const headers = {
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'cyber-hunter-lab-anti-duplicata',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
  const { ok, status, data, text } = await fetchJson(url, { headers });
  if (!ok || !Array.isArray(data)) return { source: 'GHSA', candidates: [], error: `GHSA status ${status}: ${(text || '').slice(0, 120)}` };

  const candidates = data.map((adv) => {
    const refs = (adv.references || []).map((r) => (typeof r === 'string' ? r : r.url)).filter(Boolean);
    const commits = refs.filter((u) => /\/commit\/|\/pull\//.test(u));
    return {
      id: adv.ghsa_id || adv.cve_id, source: 'GHSA',
      title: adv.summary || adv.ghsa_id,
      description: adv.description || adv.summary || '',
      url: adv.html_url || `https://github.com/advisories/${adv.ghsa_id}`,
      cwe: (adv.cwes || []).map((c) => normCwe(c.cwe_id)).filter(Boolean),
      published: adv.published_at || null,
      commits, patch_url: commits[0] || null, references: refs,
    };
  });
  return { source: 'GHSA', candidates };
}

// ---------------------------------------------------------------------
// Fonte 3 — OSV.dev (agrega GHSA, OSS-Fuzz e muitos ecossistemas)
//   Docs: https://google.github.io/osv.dev/api/
//   Melhor por PACOTE ou por COMMIT. Se o achado trouxer package/commit,
//   consultamos; senão, pulamos (OSV não faz busca por texto livre).
// ---------------------------------------------------------------------
async function queryOSV(finding) {
  const pkg = finding.package; // { name, ecosystem } opcional
  const commit = finding.commit; // hash opcional
  let body = null;
  if (commit) body = { commit };
  else if (pkg?.name) body = { package: { name: pkg.name, ecosystem: pkg.ecosystem || undefined } };
  if (!body) return { source: 'OSV', candidates: [], skipped: 'sem package/commit no achado' };

  const { ok, status, data, text } = await fetchJson('https://api.osv.dev/v1/query', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
  if (!ok || !data) return { source: 'OSV', candidates: [], error: `OSV status ${status}: ${(text || '').slice(0, 120)}` };

  const candidates = (data.vulns || []).map((v) => {
    const refs = (v.references || []).map((r) => r.url).filter(Boolean);
    return {
      id: v.id, source: 'OSV', title: v.summary || v.id,
      description: v.details || v.summary || '',
      url: `https://osv.dev/vulnerability/${v.id}`,
      cwe: [], // OSV nem sempre traz CWE; a pontuação usa texto/patch
      published: v.published || null,
      commits: refs.filter((u) => /\/commit\/|\/pull\//.test(u)),
      patch_url: refs.find((u) => /fix|patch|\/commit\//i.test(u)) || null,
      references: refs,
    };
  });
  return { source: 'OSV', candidates };
}

// ---------------------------------------------------------------------
// Fonte 4 (OPCIONAL) — spider Scrapy externo para fontes só-HTML
//   (HackerOne Hacktivity público, Bugcrowd, blogs). Só é chamado se
//   SCRAPY_COLLECTOR_URL estiver setado. Contrato esperado do spider:
//   GET {SCRAPY_COLLECTOR_URL}?q=<termos> -> { candidates: [ {id,source,
//   title,description,url,published,references} ] }
// ---------------------------------------------------------------------
async function queryScrapy(finding, scrapyUrl) {
  if (!scrapyUrl) return { source: 'Scrapy', candidates: [], skipped: 'SCRAPY_COLLECTOR_URL não configurado' };
  const q = encodeURIComponent(searchTerms(finding, 6).join(' '));
  const { ok, status, data } = await fetchJson(`${scrapyUrl}?q=${q}`, {}, 15000);
  if (!ok || !data?.candidates) return { source: 'Scrapy', candidates: [], error: `Scrapy status ${status}` };
  const candidates = data.candidates.map((c) => ({
    id: c.id, source: c.source || 'Scrapy', title: c.title || c.id,
    description: c.description || '', url: c.url,
    cwe: c.cwe || [], published: c.published || null,
    commits: c.commits || [], patch_url: c.patch_url || null, references: c.references || [],
  }));
  return { source: 'Scrapy', candidates };
}

// ---------------------------------------------------------------------
// Orquestra todas as fontes em paralelo, deduplica por id, devolve tudo.
// ---------------------------------------------------------------------
export async function collectPublicDisclosures(finding, cfg = {}) {
  const { nvdApiKey, githubToken, scrapyUrl } = cfg;
  const results = await Promise.allSettled([
    queryNVD(finding, nvdApiKey),
    queryGHSA(finding, githubToken),
    queryOSV(finding),
    queryScrapy(finding, scrapyUrl),
  ]);

  const candidates = [];
  const sources_consulted = [];
  const sources_status = {};
  const seen = new Set();

  for (const r of results) {
    const val = r.status === 'fulfilled' ? r.value : { source: 'desconhecida', candidates: [], error: r.reason?.message };
    sources_status[val.source] = val.error ? `erro: ${val.error}` : val.skipped ? `pulada: ${val.skipped}` : `ok (${val.candidates.length})`;
    if (!val.skipped) sources_consulted.push(val.source);
    for (const c of val.candidates) {
      if (!c.id || seen.has(c.id)) continue;
      seen.add(c.id);
      candidates.push(c);
    }
  }

  return { candidates, sources_consulted, sources_status, collected_at: new Date().toISOString() };
}

// ---------------------------------------------------------------------
// Registra a rota no app Express. Chame registerAntiDuplicata(app) no
// server.js (veja PATCH_SERVER.md).
// ---------------------------------------------------------------------
export function registerAntiDuplicata(app, loadSettings) {
  app.post('/api/anti-duplicata', async (req, res) => {
    const finding = req.body?.finding;
    if (!finding || typeof finding !== 'object') {
      return res.status(400).json({ error: 'envie { finding: {...} }' });
    }
    const settings = loadSettings ? loadSettings() : {};
    const cfg = {
      nvdApiKey: process.env.NVD_API_KEY || settings.nvd_api_key || null,
      githubToken: process.env.GITHUB_TOKEN || settings.github_token || null,
      scrapyUrl: process.env.SCRAPY_COLLECTOR_URL || settings.scrapy_collector_url || null,
    };
    try {
      const out = await collectPublicDisclosures(finding, cfg);
      res.json(out);
    } catch (e) {
      res.status(502).json({ error: `falha na coleta: ${e.message}` });
    }
  });
}
