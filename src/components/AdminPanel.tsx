import React, { useState } from 'react';
import { motion } from 'motion/react';
import { ShieldAlert, Ban, CheckCircle2, RefreshCw, Shield, Lock, Eye, EyeOff, AlertCircle } from 'lucide-react';
import { cn } from '../lib/utils';

interface IpEntry {
  ip: string;
  used: number;
  blocked: boolean;
  subscribed: boolean;
  first_seen?: string;
  last_seen?: string;
}

interface Lead {
  email: string;
  ip: string;
  created_at: string;
}

interface TrafficSummary {
  total_events: number;
  by_source: { source: string; count: number }[];
  by_referral: { ref: string; count: number }[];
}

interface BlogPost {
  slug: string;
  title: string;
  meta_description: string;
  keywords?: string[];
  body_html?: string;
  image_url: string | null;
  published: boolean;
  created_at: string;
}

export const AdminPanel = () => {
  const [token, setToken] = useState<string>(() => sessionStorage.getItem('admin_token') || '');
  const [showPassword, setShowPassword] = useState(false);
  const [entries, setEntries] = useState<IpEntry[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // null = ainda checando; true = hospedagem sem servidor (Netlify estático)
  const [staticHosting, setStaticHosting] = useState<boolean | null>(null);
  const [subscribeUrl, setSubscribeUrl] = useState('');
  const [savingSettings, setSavingSettings] = useState(false);
  const [leads, setLeads] = useState<Lead[]>([]);
  const [traffic, setTraffic] = useState<TrafficSummary | null>(null);
  const [geminiConfigured, setGeminiConfigured] = useState(false);
  const [newApiKey, setNewApiKey] = useState('');
  const [savingApiKey, setSavingApiKey] = useState(false);
  const [apiKeySaved, setApiKeySaved] = useState(false);
  const [posts, setPosts] = useState<BlogPost[]>([]);
  const [topic, setTopic] = useState('');
  const [generating, setGenerating] = useState(false);
  const [genError, setGenError] = useState<string | null>(null);

  // Checa uma vez, ao abrir, se existe backend de verdade. Em hospedagem
  // estática o /api devolve o index.html, então não adianta pedir senha.
  React.useEffect(() => {
    let cancelado = false;
    (async () => {
      try {
        const r = await fetch('/api/settings');
        const ct = r.headers.get('content-type') || '';
        if (!cancelado) setStaticHosting(!ct.includes('application/json'));
      } catch {
        if (!cancelado) setStaticHosting(true);
      }
    })();
    return () => { cancelado = true; };
  }, []);

  const loadPosts = async (t: string) => {
    try {
      const r = await fetch(`/api/admin/blog?token=${encodeURIComponent(t)}`);
      setPosts(await r.json());
    } catch {
      // sem servidor — deixa vazio
    }
  };

  const generatePost = async () => {
    if (!topic.trim()) return;
    setGenerating(true);
    setGenError(null);
    try {
      const r = await fetch(`/api/admin/blog/generate?token=${encodeURIComponent(token)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ topic: topic.trim() }),
      });
      const data = await r.json();
      if (!r.ok) {
        setGenError(data.error || 'falha ao gerar');
        return;
      }
      setTopic('');
      loadPosts(token);
    } catch (e: any) {
      setGenError(e.message);
    } finally {
      setGenerating(false);
    }
  };

  const togglePublish = async (slug: string, published: boolean) => {
    await fetch(`/api/admin/blog/publish?token=${encodeURIComponent(token)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ slug, published }),
    });
    loadPosts(token);
  };

  const saveApiKey = async () => {
    if (!newApiKey.trim()) return;
    setSavingApiKey(true);
    setApiKeySaved(false);
    try {
      const r = await fetch(`/api/admin/api-key?token=${encodeURIComponent(token)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ gemini_api_key: newApiKey.trim() }),
      });
      if (r.ok) {
        setGeminiConfigured(true);
        setApiKeySaved(true);
        setNewApiKey('');
      }
    } finally {
      setSavingApiKey(false);
    }
  };

  const loadGrowthData = async (t: string) => {
    try {
      const [leadsResp, trafficResp] = await Promise.all([
        fetch(`/api/admin/leads?token=${encodeURIComponent(t)}`),
        fetch(`/api/admin/traffic?token=${encodeURIComponent(t)}`),
      ]);
      setLeads(await leadsResp.json());
      setTraffic(await trafficResp.json());
    } catch {
      // sem servidor — deixa vazio
    }
  };

  const loadSettings = async () => {
    try {
      const r = await fetch('/api/settings');
      const d = await r.json();
      setSubscribeUrl(d.subscribe_url || '');
      setGeminiConfigured(!!d.gemini_configured);
    } catch {
      // sem servidor disponível — deixa em branco
    }
  };

  const saveSubscribeUrl = async () => {
    setSavingSettings(true);
    try {
      await fetch(`/api/admin/settings?token=${encodeURIComponent(token)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subscribe_url: subscribeUrl }),
      });
    } finally {
      setSavingSettings(false);
    }
  };

  const load = async (t: string) => {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch(`/api/admin/ips?token=${encodeURIComponent(t)}`);
      if (resp.status === 401) {
        setError('Token inválido.');
        setEntries(null);
        return;
      }
      const ct = resp.headers.get('content-type') || '';
      if (!ct.includes('application/json')) {
        // Hospedagem estática (Netlify/GitHub Pages) não tem servidor, então
        // o /api devolve o index.html. O painel de admin só funciona numa
        // hospedagem com Node (ex: Render). Não é bug do app.
        setError('O painel de admin precisa de um servidor (Node). Nesta hospedagem estática ele não funciona — a IA do site segue funcionando normalmente para os usuários.');
        setEntries(null);
        return;
      }
      const data = await resp.json();
      setEntries(data);
      sessionStorage.setItem('admin_token', t);
      loadSettings();
      loadGrowthData(t);
      loadPosts(t);
    } catch (e: any) {
      setError(`Falha ao carregar: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const act = async (path: string, body: any) => {
    await fetch(`/api/admin/${path}?token=${encodeURIComponent(token)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    load(token);
  };

  if (staticHosting === true) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4">
        <div className="w-full max-w-md bg-[#121212]/80 backdrop-blur-xl border border-zinc-800 rounded-[2rem] p-8 md:p-12 text-center space-y-6">
          <div className="p-5 bg-amber-500/10 rounded-2xl border border-amber-500/20 inline-block">
            <AlertCircle size={40} className="text-amber-500" />
          </div>
          <h1 className="text-2xl font-black text-white tracking-tighter uppercase">
            Painel indisponível aqui
          </h1>
          <p className="text-sm text-zinc-400 leading-relaxed">
            Este site está publicado como <strong className="text-zinc-200">hospedagem
            estática</strong> (só arquivos). O painel administrativo precisa de um
            servidor Node rodando, então ele não abre nesta publicação.
          </p>
          <div className="p-4 bg-emerald-500/5 border border-emerald-500/20 rounded-xl text-left">
            <p className="text-xs text-emerald-400 font-mono uppercase tracking-widest mb-2">
              Isso não afeta o site
            </p>
            <p className="text-xs text-zinc-400 leading-relaxed">
              A chave da IA já vai embutida na publicação, então a análise funciona
              normalmente para todos os usuários — você não precisa do painel para o
              site operar.
            </p>
          </div>
          <p className="text-[11px] text-zinc-600 leading-relaxed">
            Para ter o painel (bloquear IP, trocar a chave pelo site, estatísticas),
            publique numa hospedagem com Node (ex: Render) usando
            <span className="font-mono text-zinc-500"> npm start</span>.
          </p>
          <a
            href="/"
            className="block w-full bg-[#1a1a1a] hover:bg-zinc-800 border border-zinc-800 rounded-xl py-3 text-[11px] font-mono uppercase tracking-widest text-zinc-300 transition-all"
          >
            Voltar para o site
          </a>
        </div>
      </div>
    );
  }

  if (staticHosting === null) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="w-6 h-6 border-2 border-zinc-600 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (entries === null) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="w-full max-w-md bg-[#121212]/80 backdrop-blur-xl border border-zinc-800 rounded-[2rem] p-8 md:p-12 shadow-[0_0_50px_rgba(0,0,0,0.5)]"
        >
          <div className="flex flex-col items-center mb-10">
            <div className="p-5 bg-red-500/10 rounded-2xl border border-red-500/20 mb-6 shadow-[0_0_20px_rgba(239,68,68,0.1)]">
              <Shield size={44} className="text-red-500" />
            </div>
            <h1 className="text-3xl font-black text-white tracking-tighter uppercase text-center mb-2">
              Cyber Hunter Lab
            </h1>
            <h2 className="text-[11px] font-mono font-bold text-zinc-500 tracking-[0.2em] uppercase text-center">
              Painel Administrativo
            </h2>
          </div>

          {error && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              className="mb-6 p-4 bg-amber-500/10 border border-amber-500/20 rounded-xl flex items-start gap-3"
            >
              <AlertCircle size={18} className="text-amber-500 mt-0.5 flex-shrink-0" />
              <p className="text-xs text-amber-200/80 leading-relaxed">{error}</p>
            </motion.div>
          )}

          <form onSubmit={(e) => { e.preventDefault(); load(token); }} className="space-y-6">
            <div className="space-y-2">
              <label className="text-[10px] font-mono font-bold text-zinc-500 uppercase tracking-widest flex items-center gap-2">
                <Lock size={12} /> Senha de admin
              </label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  placeholder="Senha"
                  className="w-full bg-zinc-900/50 border border-zinc-800 rounded-xl px-4 py-3 text-sm text-zinc-300 focus:outline-none focus:border-red-500/50 focus:ring-1 focus:ring-red-500/20 transition-all font-mono pr-12"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-zinc-600 hover:text-zinc-400 transition-colors"
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading || !token}
              className="w-full bg-[#1a1a1a] hover:bg-zinc-800 border border-zinc-800 rounded-xl py-3.5 flex items-center justify-center gap-3 transition-all active:scale-[0.98] disabled:opacity-50"
            >
              {loading ? (
                <div className="w-4 h-4 border-2 border-red-500 border-t-transparent rounded-full animate-spin" />
              ) : (
                <>
                  <Lock size={16} className="text-red-500" />
                  <span className="text-xs font-mono font-bold uppercase tracking-[0.2em] text-zinc-300">Acessar Painel</span>
                </>
              )}
            </button>
          </form>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="max-w-3xl mx-auto mt-8 flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-mono uppercase tracking-widest text-zinc-300 flex items-center gap-2">
          <ShieldAlert size={18} /> IPs registrados ({entries.length})
        </h2>
        <button onClick={() => load(token)} className="text-zinc-500 hover:text-zinc-300">
          <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
        </button>
      </div>

      <div className="flex flex-col gap-2 border border-zinc-800 rounded-lg p-4 bg-[#121212]">
        <label className="text-[11px] font-mono uppercase tracking-widest text-zinc-500">
          Chave da API do Gemini (fica só no servidor — {geminiConfigured ? 'já configurada ✓' : 'ainda não configurada'})
        </label>
        <div className="flex gap-2">
          <input
            type="password"
            value={newApiKey}
            onChange={(e) => setNewApiKey(e.target.value)}
            placeholder={geminiConfigured ? 'Colar nova chave pra substituir a atual' : 'Cole sua chave da API do Gemini'}
            className="flex-1 h-10 bg-[#1a1a1a] border border-zinc-800 rounded-lg px-3 font-mono text-xs text-zinc-300 focus:outline-none focus:border-zinc-600"
          />
          <button
            onClick={saveApiKey}
            disabled={savingApiKey || !newApiKey.trim()}
            className="px-4 rounded-lg bg-emerald-700 hover:bg-emerald-600 disabled:opacity-40 text-xs font-mono text-white"
          >
            {savingApiKey ? 'Salvando...' : 'Salvar chave'}
          </button>
        </div>
        {apiKeySaved && <p className="text-[11px] text-emerald-400">✓ Chave salva. Usuários não precisam mais colar a própria.</p>}
        <p className="text-[10px] text-zinc-600">
          Por segurança, a chave nunca é reexibida depois de salva — só confirma se está configurada ou não.
        </p>
      </div>

      <div className="flex flex-col gap-3 border border-zinc-800 rounded-lg p-4 bg-[#121212]">
        <label className="text-[11px] font-mono uppercase tracking-widest text-zinc-500">
          Blog — gerar artigo (2 agentes: redator + editor SEO)
        </label>
        <div className="flex gap-2">
          <input
            value={topic}
            onChange={(e) => setTopic(e.target.value)}
            placeholder="Tema do artigo (ex: como prevenir path traversal em Node.js)"
            className="flex-1 h-10 bg-[#1a1a1a] border border-zinc-800 rounded-lg px-3 font-mono text-xs text-zinc-300 focus:outline-none focus:border-zinc-600"
          />
          <button
            onClick={generatePost}
            disabled={generating || !topic.trim()}
            className="px-4 rounded-lg bg-emerald-700 hover:bg-emerald-600 disabled:opacity-40 text-xs font-mono text-white whitespace-nowrap"
          >
            {generating ? 'Gerando...' : 'Gerar artigo'}
          </button>
        </div>
        {genError && <p className="text-[11px] text-red-400">{genError}</p>}

        <div className="flex flex-col gap-2 mt-2">
          {posts.length === 0 && <p className="text-xs text-zinc-700 font-mono">Nenhum artigo gerado ainda.</p>}
          {posts.map((p) => (
            <div key={p.slug} className="flex items-center justify-between gap-3 border border-zinc-900 rounded-lg px-3 py-2 text-xs font-mono">
              <div className="flex items-center gap-2 min-w-0">
                {p.image_url ? (
                  <img src={p.image_url} alt="" className="w-10 h-10 rounded object-cover shrink-0" />
                ) : (
                  <div className="w-10 h-10 rounded bg-zinc-800 shrink-0" />
                )}
                <div className="min-w-0">
                  <p className="text-zinc-200 truncate">{p.title}</p>
                  <p className="text-zinc-600 truncate">{p.meta_description}</p>
                </div>
              </div>
              <button
                onClick={() => togglePublish(p.slug, !p.published)}
                className={cn(
                  'px-3 py-1.5 rounded whitespace-nowrap',
                  p.published ? 'bg-emerald-900/40 text-emerald-400' : 'bg-zinc-800 text-zinc-300 hover:bg-zinc-700'
                )}
              >
                {p.published ? 'Publicado ✓' : 'Publicar'}
              </button>
            </div>
          ))}
        </div>
      </div>

      <div className="flex flex-col gap-2 border border-zinc-800 rounded-lg p-4 bg-[#121212]">
        <label className="text-[11px] font-mono uppercase tracking-widest text-zinc-500">
          Link do botão "Assinar agora"
        </label>
        <div className="flex gap-2">
          <input
            value={subscribeUrl}
            onChange={(e) => setSubscribeUrl(e.target.value)}
            placeholder="https://seu-link-de-pagamento.com"
            className="flex-1 h-10 bg-[#1a1a1a] border border-zinc-800 rounded-lg px-3 font-mono text-xs text-zinc-300 focus:outline-none focus:border-zinc-600"
          />
          <button
            onClick={saveSubscribeUrl}
            disabled={savingSettings}
            className="px-4 rounded-lg bg-emerald-700 hover:bg-emerald-600 disabled:opacity-40 text-xs font-mono text-white"
          >
            {savingSettings ? 'Salvando...' : 'Salvar'}
          </button>
        </div>
      </div>

      {traffic && (
        <div className="flex flex-col gap-2 border border-zinc-800 rounded-lg p-4 bg-[#121212]">
          <label className="text-[11px] font-mono uppercase tracking-widest text-zinc-500">
            Origem dos visitantes ({traffic.total_events} eventos)
          </label>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div>
              <p className="text-zinc-500 mb-1">Por UTM source:</p>
              {traffic.by_source.length === 0 && <p className="text-zinc-700">Sem dados ainda.</p>}
              {traffic.by_source.map((s) => (
                <div key={s.source} className="flex justify-between text-zinc-300">
                  <span>{s.source}</span><span>{s.count}</span>
                </div>
              ))}
            </div>
            <div>
              <p className="text-zinc-500 mb-1">Por link de indicação:</p>
              {traffic.by_referral.length === 0 && <p className="text-zinc-700">Sem dados ainda.</p>}
              {traffic.by_referral.map((r) => (
                <div key={r.ref} className="flex justify-between text-zinc-300">
                  <span>{r.ref}</span><span>{r.count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      <div className="flex flex-col gap-2 border border-zinc-800 rounded-lg p-4 bg-[#121212]">
        <label className="text-[11px] font-mono uppercase tracking-widest text-zinc-500">
          Lista de e-mails capturados ({leads.length})
        </label>
        <div className="flex flex-col gap-1 max-h-48 overflow-y-auto text-xs font-mono">
          {leads.length === 0 && <p className="text-zinc-700">Nenhum e-mail ainda.</p>}
          {leads.map((l, i) => (
            <div key={i} className="flex justify-between text-zinc-300 border-b border-zinc-900 py-1">
              <span>{l.email}</span>
              <span className="text-zinc-600">{l.created_at?.slice(0, 10)}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="flex flex-col gap-2">
        {entries.length === 0 && (
          <p className="text-xs text-zinc-600 font-mono">Nenhum IP registrado ainda.</p>
        )}
        {entries.map((e) => (
          <div
            key={e.ip}
            className={cn(
              'flex flex-wrap items-center justify-between gap-3 border rounded-lg px-4 py-3 text-xs font-mono',
              e.blocked ? 'border-red-900 bg-red-950/20' : 'border-zinc-800 bg-[#121212]'
            )}
          >
            <div className="flex flex-col gap-0.5">
              <span className="text-zinc-200">{e.ip}</span>
              <span className="text-zinc-500">
                {e.used} análise(s) usada(s) · último acesso: {e.last_seen || '—'}
              </span>
            </div>
            <div className="flex items-center gap-2">
              {e.subscribed && (
                <span className="px-2 py-1 rounded bg-emerald-900/40 text-emerald-400">assinante</span>
              )}
              {e.blocked ? (
                <button
                  onClick={() => act('block', { ip: e.ip, blocked: false })}
                  className="flex items-center gap-1 px-3 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200"
                >
                  <CheckCircle2 size={12} /> Desbloquear
                </button>
              ) : (
                <button
                  onClick={() => act('block', { ip: e.ip, blocked: true })}
                  className="flex items-center gap-1 px-3 py-1.5 rounded bg-red-900/40 hover:bg-red-900/60 text-red-300"
                >
                  <Ban size={12} /> Bloquear
                </button>
              )}
              <button
                onClick={() => act('subscribe', { ip: e.ip, subscribed: !e.subscribed })}
                className="px-3 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200"
              >
                {e.subscribed ? 'Remover assinatura' : 'Marcar como assinante'}
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
