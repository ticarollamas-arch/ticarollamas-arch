import express from 'express';
import path from 'path';
import dns from 'dns';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { registerAntiDuplicata } from './server_anti_duplicata.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
app.use(express.json());

// Necessário pra enxergar o IP real do visitante quando a hospedagem usa
// um proxy reverso na frente (praticamente todo painel de hospedagem usa).
app.set('trust proxy', true);

// ---------------------------------------------------------------------
// Modo demonstração com controle por IP (não só localStorage).
// Guardado em um arquivo JSON simples — ok pro tamanho de uso de um app
// solo; se crescer muito, trocar por um banco de verdade (Postgres/Mongo).
// ---------------------------------------------------------------------
const TRIAL_LIMIT_SERVER = 3;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'TROQUE-ESSE-TOKEN-ANTES-DE-IR-AO-AR';
const STORE_PATH = path.join(__dirname, 'trial_store.json');

function loadStore() {
  try {
    return JSON.parse(fs.readFileSync(STORE_PATH, 'utf8'));
  } catch {
    return {};
  }
}

function saveStore(store) {
  fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2));
}

function getEntry(store, ip) {
  return store[ip] || { used: 0, blocked: false, subscribed: false, first_seen: new Date().toISOString() };
}

app.get('/api/trial/status', (req, res) => {
  const ip = req.ip;
  const store = loadStore();
  const entry = getEntry(store, ip);
  res.json({ ip, limit: TRIAL_LIMIT_SERVER, ...entry });
});

app.post('/api/trial/consume', (req, res) => {
  const ip = req.ip;
  const store = loadStore();
  const entry = getEntry(store, ip);

  if (entry.blocked) {
    return res.status(403).json({ error: 'Este IP foi bloqueado.', ip, ...entry });
  }
  if (!entry.subscribed && entry.used >= TRIAL_LIMIT_SERVER) {
    return res.status(402).json({ error: 'Limite de análises grátis atingido.', ip, limit: TRIAL_LIMIT_SERVER, ...entry });
  }

  entry.used += 1;
  entry.last_seen = new Date().toISOString();
  store[ip] = entry;
  saveStore(store);
  res.json({ ip, limit: TRIAL_LIMIT_SERVER, ...entry });
});

function requireAdmin(req, res, next) {
  const token = req.query.token || req.headers['x-admin-token'];
  if (token !== ADMIN_TOKEN) {
    return res.status(401).json({ error: 'token de admin inválido' });
  }
  next();
}

// Lista todos os IPs já vistos, com uso/bloqueio/assinatura de cada um.
app.get('/api/admin/ips', requireAdmin, (req, res) => {
  const store = loadStore();
  const list = Object.entries(store)
    .map(([ip, v]) => ({ ip, ...v }))
    .sort((a, b) => (b.last_seen || '').localeCompare(a.last_seen || ''));
  res.json(list);
});

app.post('/api/admin/block', requireAdmin, (req, res) => {
  const { ip, blocked } = req.body || {};
  if (!ip) return res.status(400).json({ error: 'informe ip' });
  const store = loadStore();
  store[ip] = { ...getEntry(store, ip), blocked: !!blocked };
  saveStore(store);
  res.json({ ip, blocked: !!blocked });
});

app.post('/api/admin/subscribe', requireAdmin, (req, res) => {
  const { ip, subscribed } = req.body || {};
  if (!ip) return res.status(400).json({ error: 'informe ip' });
  const store = loadStore();
  store[ip] = { ...getEntry(store, ip), subscribed: !!subscribed };
  saveStore(store);
  res.json({ ip, subscribed: !!subscribed });
});

// ---------------------------------------------------------------------
// Growth: captura de e-mail (lista de espera) + rastreamento de origem
// (UTM) e de indicação (referral). Tudo em arquivos JSON simples.
// ---------------------------------------------------------------------
const LEADS_PATH = path.join(__dirname, 'leads.json');
const TRAFFIC_PATH = path.join(__dirname, 'traffic_log.json');
const MAX_TRAFFIC_ENTRIES = 5000;

function loadJsonArray(p) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return []; }
}
function saveJsonArray(p, arr) {
  fs.writeFileSync(p, JSON.stringify(arr, null, 2));
}

app.post('/api/leads', (req, res) => {
  const { email } = req.body || {};
  if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ error: 'e-mail inválido' });
  }
  const leads = loadJsonArray(LEADS_PATH);
  leads.push({ email, ip: req.ip, created_at: new Date().toISOString() });
  saveJsonArray(LEADS_PATH, leads);
  res.json({ ok: true });
});

app.get('/api/admin/leads', requireAdmin, (req, res) => {
  res.json(loadJsonArray(LEADS_PATH).reverse());
});

app.post('/api/track', (req, res) => {
  const { utm_source, utm_medium, utm_campaign, ref } = req.body || {};
  if (!utm_source && !utm_medium && !utm_campaign && !ref) {
    return res.json({ ok: true }); // nada pra registrar
  }
  const log = loadJsonArray(TRAFFIC_PATH);
  log.push({
    utm_source: utm_source || null,
    utm_medium: utm_medium || null,
    utm_campaign: utm_campaign || null,
    ref: ref || null,
    ip: req.ip,
    created_at: new Date().toISOString(),
  });
  while (log.length > MAX_TRAFFIC_ENTRIES) log.shift();
  saveJsonArray(TRAFFIC_PATH, log);
  res.json({ ok: true });
});

app.get('/api/admin/traffic', requireAdmin, (req, res) => {
  const log = loadJsonArray(TRAFFIC_PATH);
  const bySource = {};
  const byRef = {};
  for (const entry of log) {
    const src = entry.utm_source || '(direto/sem utm)';
    bySource[src] = (bySource[src] || 0) + 1;
    if (entry.ref) byRef[entry.ref] = (byRef[entry.ref] || 0) + 1;
  }
  res.json({
    total_events: log.length,
    by_source: Object.entries(bySource).sort((a, b) => b[1] - a[1]).map(([source, count]) => ({ source, count })),
    by_referral: Object.entries(byRef).sort((a, b) => b[1] - a[1]).map(([ref, count]) => ({ ref, count })),
  });
});

// ---------------------------------------------------------------------
// Configurações editáveis pelo admin (ex: link do botão "Assinar agora").
// Qualquer um pode LER (o app precisa mostrar o link certo pra todo
// visitante); só o admin com token pode ALTERAR.
// A chave do Gemini fica no MESMO arquivo mas NUNCA é devolvida pelo
// endpoint público — só o proxy /api/gemini-proxy usa ela internamente.
// ---------------------------------------------------------------------
const SETTINGS_PATH = path.join(__dirname, 'settings.json');
const DEFAULT_SETTINGS = { subscribe_url: 'https://SEU-LINK-DE-ASSINATURA-AQUI', gemini_api_key: '' };

function loadSettings() {
  try {
    return { ...DEFAULT_SETTINGS, ...JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf8')) };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}
function saveSettings(settings) {
  fs.writeFileSync(SETTINGS_PATH, JSON.stringify(settings, null, 2));
}

app.get('/api/settings', (req, res) => {
  const { gemini_api_key, ...publicSettings } = loadSettings();
  res.json({ ...publicSettings, gemini_configured: !!gemini_api_key });
});

app.post('/api/admin/settings', requireAdmin, (req, res) => {
  const current = loadSettings();
  const { gemini_api_key, ...rest } = req.body || {}; // chave só muda pelo endpoint dedicado abaixo
  const updated = { ...current, ...rest };
  saveSettings(updated);
  const { gemini_api_key: _omit, ...publicSettings } = updated;
  res.json(publicSettings);
});

// Só o admin define a chave. Nunca é lida de volta (nem pra ele) — só
// sobrescrita. Confirma sucesso, não devolve o valor.
app.post('/api/admin/api-key', requireAdmin, (req, res) => {
  const { gemini_api_key } = req.body || {};
  if (typeof gemini_api_key !== 'string' || !gemini_api_key.trim()) {
    return res.status(400).json({ error: 'informe gemini_api_key' });
  }
  const current = loadSettings();
  saveSettings({ ...current, gemini_api_key: gemini_api_key.trim() });
  res.json({ ok: true, gemini_configured: true });
});

// ---------------------------------------------------------------------
// /api/gemini-proxy — repassa a chamada pro Gemini usando a chave salva
// no servidor. O visitante NUNCA vê a chave real; o navegador só manda
// o corpo da requisição (prompt, schema, etc.) e recebe a resposta.
// ---------------------------------------------------------------------
app.post('/api/gemini-proxy', async (req, res) => {
  const { model, body } = req.body || {};
  if (!model || !body) return res.status(400).json({ error: 'informe model e body' });

  const { gemini_api_key } = loadSettings();
  if (!gemini_api_key) {
    return res.status(503).json({ error: 'Nenhuma chave Gemini configurada no servidor ainda.' });
  }

  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 60000);
    const r = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${gemini_api_key}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal,
      }
    );
    clearTimeout(t);
    const data = await r.json();
    if (!r.ok) {
      return res.status(r.status).json({ error: data?.error?.message || 'erro na API do Gemini' });
    }
    res.json(data);
  } catch (e) {
    res.status(502).json({ error: `falha ao chamar Gemini: ${e.message}` });
  }
});

// ---------------------------------------------------------------------
// Blog automático: 2 agentes (Redator SEO + Editor SEO) escrevem o
// artigo, e um terceiro passo gera a imagem de capa. Publicação fica
// sob revisão do admin antes de aparecer no /blog público.
//
// IMPORTANTE — honestidade: não existe aqui nenhum dado real de Google
// Trends/volume de busca. O tema vem de quem pedir (admin), e o
// conteúdo é gerado com conhecimento geral da IA, não dado de busca
// ao vivo. A geração de imagem é a parte MENOS testada deste arquivo
// inteiro (sem internet neste sandbox pra confirmar o endpoint do
// Imagen) — se falhar, o artigo publica sem imagem em vez de travar.
// ---------------------------------------------------------------------
const BLOG_PATH = path.join(__dirname, 'blog_posts.json');

function loadBlogPosts() {
  return loadJsonArray(BLOG_PATH);
}
function saveBlogPosts(posts) {
  saveJsonArray(BLOG_PATH, posts);
}
function slugify(title) {
  return title
    .toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '') // remove acentos
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '')
    .slice(0, 80);
}

async function callGeminiJSON(model, systemInstruction, userPrompt, responseSchema, apiKey) {
  const body = {
    contents: [{ parts: [{ text: userPrompt }] }],
    systemInstruction: { parts: [{ text: systemInstruction }] },
    generationConfig: { temperature: 0.7, responseMimeType: 'application/json', responseSchema },
  };
  const r = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
  );
  const data = await r.json();
  if (!r.ok) throw new Error(data?.error?.message || `Gemini retornou ${r.status}`);
  const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!text) throw new Error('resposta do Gemini sem texto');
  return JSON.parse(text);
}

async function generateCoverImage(prompt, apiKey) {
  // Melhor esforço: se o modelo/endpoint de imagem falhar, retorna null
  // e o artigo é publicado sem imagem (não trava o fluxo).
  try {
    const r = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/imagen-3.0-generate-002:predict?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ instances: [{ prompt }], parameters: { sampleCount: 1 } }),
      }
    );
    const data = await r.json();
    const b64 = data?.predictions?.[0]?.bytesBase64Encoded;
    return b64 ? `data:image/png;base64,${b64}` : null;
  } catch {
    return null;
  }
}

const AGENT_WRITER = `Você é um redator SEO sênior, especialista em artigos técnicos de segurança/tecnologia.
Escreva um artigo completo e ORIGINAL sobre o tema pedido. Nada de enrolação genérica.
Estrutura: H1 (título), introdução, 3-5 seções H2 com profundidade real, conclusão com CTA.
Retorne JSON estrito: { "title": "...", "meta_description": "...(máx 155 caracteres)...", "keywords": ["...","..."], "body_html": "<h1>...</h1>...", "image_prompt": "descrição visual em inglês pra gerar a imagem de capa" }`;

const AGENT_EDITOR = `Você é um editor SEO implacável. Revise o rascunho abaixo:
- Corte qualquer frase genérica de "AI slop" (clichês, floreios sem informação real).
- Garanta que as keywords aparecem naturalmente no texto, sem forçar.
- Garanta title <= 60 caracteres e meta_description <= 155 caracteres.
- Devolva o artigo FINAL no mesmo formato JSON de entrada, já corrigido.`;

app.post('/api/admin/blog/generate', requireAdmin, async (req, res) => {
  const { topic } = req.body || {};
  if (!topic) return res.status(400).json({ error: 'informe topic' });
  const { gemini_api_key } = loadSettings();
  if (!gemini_api_key) return res.status(503).json({ error: 'configure a chave do Gemini primeiro' });

  const schema = {
    type: 'OBJECT',
    properties: {
      title: { type: 'STRING' },
      meta_description: { type: 'STRING' },
      keywords: { type: 'ARRAY', items: { type: 'STRING' } },
      body_html: { type: 'STRING' },
      image_prompt: { type: 'STRING' },
    },
    required: ['title', 'meta_description', 'keywords', 'body_html', 'image_prompt'],
  };

  try {
    const draft = await callGeminiJSON('gemini-2.5-flash', AGENT_WRITER, `Tema: ${topic}`, schema, gemini_api_key);
    const final = await callGeminiJSON('gemini-2.5-flash', AGENT_EDITOR, JSON.stringify(draft), schema, gemini_api_key);
    const image_url = await generateCoverImage(final.image_prompt, gemini_api_key);

    const post = {
      slug: slugify(final.title) + '-' + Date.now().toString(36),
      title: final.title,
      meta_description: final.meta_description,
      keywords: final.keywords,
      body_html: final.body_html,
      image_url,
      published: false, // admin revisa antes de publicar
      created_at: new Date().toISOString(),
    };
    const posts = loadBlogPosts();
    posts.unshift(post);
    saveBlogPosts(posts);
    res.json(post);
  } catch (e) {
    res.status(502).json({ error: `falha ao gerar artigo: ${e.message}` });
  }
});

app.get('/api/admin/blog', requireAdmin, (req, res) => {
  res.json(loadBlogPosts());
});

app.post('/api/admin/blog/publish', requireAdmin, (req, res) => {
  const { slug, published } = req.body || {};
  const posts = loadBlogPosts();
  const post = posts.find((p) => p.slug === slug);
  if (!post) return res.status(404).json({ error: 'artigo não encontrado' });
  post.published = !!published;
  saveBlogPosts(posts);
  res.json(post);
});

app.get('/api/blog', (req, res) => {
  const posts = loadBlogPosts()
    .filter((p) => p.published)
    .map(({ slug, title, meta_description, image_url, created_at }) => ({ slug, title, meta_description, image_url, created_at }));
  res.json(posts);
});

app.get('/api/blog/:slug', (req, res) => {
  const post = loadBlogPosts().find((p) => p.slug === req.params.slug && p.published);
  if (!post) return res.status(404).json({ error: 'não encontrado' });
  res.json(post);
});

app.get('/sitemap.xml', (req, res) => {
  const posts = loadBlogPosts().filter((p) => p.published);
  const host = `${req.protocol}://${req.get('host')}`;
  const urls = [host, ...posts.map((p) => `${host}/blog/${p.slug}`)]
    .map((u) => `<url><loc>${u}</loc></url>`)
    .join('');
  res.type('application/xml').send(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls}</urlset>`);
});

// ---------------------------------------------------------------------
// /api/github-fetch — busca o ARQUIVO INTEIRO real de um repositório
// público do GitHub (não um trecho colado à mão). Isso existe porque um
// trecho isolado pode esconder uma função vizinha que já faz a validação
// de segurança — like aconteceu no caso do SafeMakeDir/doSafeMakeDir do
// Kubernetes. Só aceita URLs do próprio github.com (allowlist fixa).
// ---------------------------------------------------------------------
function parseGithubBlobUrl(url) {
  const m = url.match(/^https:\/\/github\.com\/([^/]+)\/([^/]+)\/blob\/([^/]+)\/(.+)$/);
  if (!m) return null;
  const [, owner, repo, ref, filePath] = m;
  return {
    owner, repo, ref, filePath,
    rawUrl: `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${filePath}`,
  };
}

app.get('/api/github-fetch', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: 'informe ?url=' });
  const parsed = parseGithubBlobUrl(url);
  if (!parsed) {
    return res.status(400).json({ error: 'só aceito URLs no formato https://github.com/OWNER/REPO/blob/REF/CAMINHO' });
  }
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 8000);
    const r = await fetch(parsed.rawUrl, { signal: controller.signal });
    clearTimeout(t);
    if (!r.ok) {
      return res.status(r.status).json({ error: `GitHub retornou ${r.status} para ${parsed.rawUrl}` });
    }
    const content = await r.text();
    res.json({ ...parsed, content, size_bytes: content.length });
  } catch (e) {
    res.status(502).json({ error: `falha ao buscar do GitHub: ${e.message}` });
  }
});

// ---------------------------------------------------------------------
// /api/recon — reconhecimento PASSIVO e ético de um único alvo por vez.
// Só faz requisições GET normais (as mesmas que qualquer navegador faria):
// headers de segurança, robots.txt, exposição de .git/HEAD.
// NÃO envia payloads, NÃO tenta explorar nada.
// Bloqueia IPs privados/internos para não virar um proxy de SSRF.
// ---------------------------------------------------------------------
function isPrivateIp(ip) {
  if (ip.includes(':')) {
    // IPv6: bloqueia loopback (::1) e link-local (fe80::/10)
    return ip === '::1' || ip.toLowerCase().startsWith('fe80:');
  }
  const parts = ip.split('.').map(Number);
  const [a, b] = parts;
  if (a === 127) return true;              // loopback
  if (a === 10) return true;               // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 169 && b === 254) return true; // link-local
  if (a === 0) return true;
  return false;
}

async function safeFetch(url, opts = {}) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('protocolo não permitido');
  }
  const { address } = await dns.promises.lookup(parsed.hostname);
  if (isPrivateIp(address)) {
    throw new Error('alvo aponta para rede interna/privada — bloqueado');
  }
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), 8000);
  try {
    return await fetch(url, { redirect: 'manual', signal: controller.signal, ...opts });
  } finally {
    clearTimeout(t);
  }
}

app.get('/api/recon', async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).json({ error: 'informe ?url=' });

  let base;
  try {
    base = new URL(target);
  } catch {
    return res.status(400).json({ error: 'URL inválida' });
  }

  const findings = { target: base.toString(), checked_at: new Date().toISOString() };

  try {
    const r = await safeFetch(base.toString());
    findings.status = r.status;
    const h = Object.fromEntries(r.headers.entries());
    findings.security_headers = {
      'strict-transport-security': h['strict-transport-security'] || null,
      'content-security-policy': h['content-security-policy'] || null,
      'x-frame-options': h['x-frame-options'] || null,
      'x-content-type-options': h['x-content-type-options'] || null,
      'referrer-policy': h['referrer-policy'] || null,
      'set-cookie_flags': h['set-cookie'] || null,
    };
    findings.server_banner = h['server'] || null;
    findings.powered_by = h['x-powered-by'] || null;
  } catch (e) {
    findings.error = `falha ao acessar o alvo: ${e.message}`;
    return res.json(findings);
  }

  // robots.txt (passivo, só leitura)
  try {
    const rr = await safeFetch(new URL('/robots.txt', base).toString());
    findings.robots_txt = rr.status === 200 ? (await rr.text()).slice(0, 1000) : `status ${rr.status}`;
  } catch (e) {
    findings.robots_txt = `erro: ${e.message}`;
  }

  // exposição de .git (só checa status, não baixa nada além do HEAD)
  try {
    const gr = await safeFetch(new URL('/.git/HEAD', base).toString());
    findings.git_exposed = gr.status === 200;
  } catch (e) {
    findings.git_exposed = null;
  }

  res.json(findings);
});

// ---------------------------------------------------------------------
// Módulo Anti-Duplicata: rota POST /api/anti-duplicata (coleta de fontes
// públicas). loadSettings é reutilizada para pegar chaves opcionais
// (nvd_api_key, github_token, scrapy_collector_url) sem expô-las ao front.
// ---------------------------------------------------------------------
registerAntiDuplicata(app, loadSettings);

// Serve os arquivos estáticos gerados por "npm run build" (pasta dist/)
app.use(express.static(path.join(__dirname, 'dist')));

// Qualquer rota cai no index.html (SPA)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Cyber Hunter Lab rodando na porta ${PORT}`);
});
