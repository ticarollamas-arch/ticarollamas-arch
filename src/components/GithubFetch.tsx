import React, { useState } from 'react';
import { Github, Search, Loader2 } from 'lucide-react';

interface GithubFetchProps {
  onFetched: (content: string, meta: { owner: string; repo: string; filePath: string }) => void;
}

export const GithubFetch = ({ onFetched }: GithubFetchProps) => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastFetch, setLastFetch] = useState<string | null>(null);

  const runFetch = async () => {
    if (!url.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch(`/api/github-fetch?url=${encodeURIComponent(url.trim())}`);
      const data = await resp.json();
      if (!resp.ok) {
        setError(data.error || 'Falha ao buscar arquivo.');
        return;
      }
      onFetched(data.content, { owner: data.owner, repo: data.repo, filePath: data.filePath });
      setLastFetch(`${data.filePath} (${data.size_bytes} bytes) — arquivo COMPLETO, não um trecho`);
    } catch (e: any) {
      setError(`Falha ao buscar: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col gap-2 w-full">
      <div className="flex items-center gap-2 px-1">
        <Github size={14} className="text-zinc-500" />
        <label className="text-[11px] font-mono uppercase tracking-widest text-zinc-500 italic opacity-70">
          Buscar arquivo REAL do GitHub (evita analisar trecho incompleto)
        </label>
      </div>
      <div className="flex gap-2">
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://github.com/owner/repo/blob/main/caminho/arquivo.go"
          className="flex-1 h-11 bg-[#1a1a1a] border border-zinc-800 rounded-lg px-3 font-mono text-sm text-zinc-300 focus:outline-none focus:border-zinc-600"
        />
        <button
          type="button"
          onClick={runFetch}
          disabled={loading || !url.trim()}
          className="flex items-center gap-2 px-4 rounded-lg bg-emerald-700 hover:bg-emerald-600 disabled:opacity-40 text-sm font-mono text-white"
        >
          {loading ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
          Buscar arquivo real
        </button>
      </div>
      <p className="text-[10px] text-zinc-600 px-1">
        Traz o arquivo INTEIRO (não uma função isolada), pra IA enxergar
        funções vizinhas que já podem validar o mesmo caminho.
      </p>
      {error && <p className="text-[11px] text-red-400 px-1">{error}</p>}
      {lastFetch && !error && <p className="text-[11px] text-emerald-400 px-1">✓ {lastFetch}</p>}
    </div>
  );
};
