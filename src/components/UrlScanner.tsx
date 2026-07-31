import React, { useState } from 'react';
import { Globe, Search, Loader2 } from 'lucide-react';
import { cn } from '../lib/utils';

interface UrlScannerProps {
  // Recebe o texto de evidências já formatado, pra você colar no campo
  // de código e clicar em "Analisar" manualmente (sem nada automático).
  onEvidenceReady: (evidenceText: string) => void;
}

export const UrlScanner = ({ onEvidenceReady }: UrlScannerProps) => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runRecon = async () => {
    if (!url.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch(`/api/recon?url=${encodeURIComponent(url.trim())}`);
      const ct = resp.headers.get('content-type') || '';
      if (!ct.includes('application/json')) {
        setError('O coletor de evidências precisa de um servidor (Node) e não funciona nesta hospedagem estática. Você ainda pode colar o código ou anexar a pasta para analisar.');
        return;
      }
      const data = await resp.json();
      if (data.error && !data.status) {
        setError(data.error);
        return;
      }
      const lines = [
        `EVIDÊNCIA DE RECONHECIMENTO PASSIVO — ${data.target}`,
        `Coletado em: ${data.checked_at}`,
        `Status HTTP: ${data.status}`,
        `Servidor: ${data.server_banner || 'não informado'}`,
        `X-Powered-By: ${data.powered_by || 'não informado'}`,
        '',
        'Cabeçalhos de segurança:',
        `  Strict-Transport-Security: ${data.security_headers?.['strict-transport-security'] || 'AUSENTE'}`,
        `  Content-Security-Policy: ${data.security_headers?.['content-security-policy'] || 'AUSENTE'}`,
        `  X-Frame-Options: ${data.security_headers?.['x-frame-options'] || 'AUSENTE'}`,
        `  X-Content-Type-Options: ${data.security_headers?.['x-content-type-options'] || 'AUSENTE'}`,
        `  Referrer-Policy: ${data.security_headers?.['referrer-policy'] || 'AUSENTE'}`,
        '',
        `robots.txt: ${data.robots_txt ? data.robots_txt.slice(0, 300) : 'não verificado'}`,
        `.git exposto publicamente: ${data.git_exposed === true ? 'SIM (risco)' : data.git_exposed === false ? 'não' : 'não verificado'}`,
      ].join('\n');
      onEvidenceReady(lines);
    } catch (e: any) {
      setError(`Falha ao coletar evidências: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col gap-2 w-full">
      <div className="flex items-center gap-2 px-1">
        <Globe size={14} className="text-zinc-500" />
        <label className="text-[11px] font-mono uppercase tracking-widest text-zinc-500 italic opacity-70">
          URL do alvo (dentro do escopo autorizado)
        </label>
      </div>
      <div className="flex gap-2">
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://exemplo.com"
          className="flex-1 h-11 bg-[#1a1a1a] border border-zinc-800 rounded-lg px-3 font-mono text-sm text-zinc-300 focus:outline-none focus:border-zinc-600"
        />
        <button
          type="button"
          onClick={runRecon}
          disabled={loading || !url.trim()}
          className="flex items-center gap-2 px-4 rounded-lg bg-emerald-700 hover:bg-emerald-600 disabled:opacity-40 text-sm font-mono text-white"
        >
          {loading ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
          Coletar evidências
        </button>
      </div>
      <p className="text-[10px] text-zinc-600 px-1">
        Só faz requisições GET normais (headers, robots.txt, checagem de .git exposto).
        Nenhum payload é enviado. Depois de coletar, clique em "Analisar" pra gerar o relatório.
      </p>
      {error && <p className="text-[11px] text-red-400 px-1">{error}</p>}
    </div>
  );
};
