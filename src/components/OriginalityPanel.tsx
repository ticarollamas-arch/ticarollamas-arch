import React from 'react';
import { motion } from 'motion/react';
import {
  ShieldCheck, ShieldAlert, ShieldQuestion, Fingerprint, ExternalLink,
  GitCommit, Calendar, AlertTriangle, Search, Loader2, RefreshCw,
} from 'lucide-react';
import { Badge } from './ui/Badge';
import { cn } from '../lib/utils';
import type { OriginalityAnalysis, ScoredCandidate } from '../lib/antiDuplicata';

interface Props {
  analysis: OriginalityAnalysis | null;
  loading?: boolean;
  error?: string | null;
  onRun?: () => void;
}

// Cor/ícone/rótulo por classificação.
function theme(label: OriginalityAnalysis['label']) {
  switch (label) {
    case 'alta':
      return { color: 'text-red-500', ring: 'border-red-500/30', bg: 'bg-red-500/5',
        bar: 'bg-red-500', variant: 'danger' as const, Icon: ShieldAlert,
        text: 'Alta probabilidade de duplicata' };
    case 'media':
      return { color: 'text-amber-500', ring: 'border-amber-500/30', bg: 'bg-amber-500/5',
        bar: 'bg-amber-500', variant: 'warning' as const, Icon: ShieldQuestion,
        text: 'Similaridade média' };
    default:
      return { color: 'text-emerald-500', ring: 'border-emerald-500/30', bg: 'bg-emerald-500/5',
        bar: 'bg-emerald-500', variant: 'success' as const, Icon: ShieldCheck,
        text: 'Nenhuma correspondência relevante' };
  }
}

export function OriginalityPanel({ analysis, loading, error, onRun }: Props) {
  return (
    <section className="bg-[#1a1a1a] border border-zinc-800 rounded-lg overflow-hidden">
      <div className="bg-zinc-900 px-6 py-3 border-b border-zinc-800 flex items-center justify-between">
        <h3 className="text-[11px] font-mono uppercase tracking-widest text-zinc-400 flex items-center gap-2">
          <Search size={14} className="text-zinc-500" /> Análise de Originalidade · Anti-Duplicata
        </h3>
        {onRun && (
          <button
            onClick={onRun}
            disabled={loading}
            className="flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-wider text-zinc-300 hover:text-white bg-zinc-800 hover:bg-zinc-700 disabled:opacity-50 px-2.5 py-1 rounded transition-colors"
          >
            {loading ? <Loader2 size={12} className="animate-spin" /> : <RefreshCw size={12} />}
            {analysis ? 'Rechecar' : 'Checar'}
          </button>
        )}
      </div>

      <div className="p-6">
        {error && (
          <div className="text-red-400 text-sm font-mono bg-red-500/5 border border-red-500/20 rounded p-3">
            Falha na coleta: {error}
          </div>
        )}

        {loading && !analysis && (
          <div className="flex items-center gap-2 text-zinc-400 text-sm">
            <Loader2 size={16} className="animate-spin" /> Consultando fontes públicas (CVE/NVD, GHSA, OSV…)
          </div>
        )}

        {!loading && !analysis && !error && (
          <p className="text-zinc-500 text-sm">
            Ainda não checado. A checagem pesquisa se a vulnerabilidade já foi divulgada
            publicamente — para auxiliar a triagem, <span className="text-zinc-300">sem afirmar</span> que é duplicata.
          </p>
        )}

        {analysis && <Result analysis={analysis} />}
      </div>
    </section>
  );
}

function Result({ analysis }: { analysis: OriginalityAnalysis }) {
  const t = theme(analysis.label);
  return (
    <div className="space-y-5">
      {/* Cabeçalho: score + indicador */}
      <div className={cn('flex items-center gap-4 rounded-lg border p-4', t.ring, t.bg)}>
        <div className="text-4xl leading-none">{analysis.indicator}</div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={cn('text-2xl font-bold font-mono', t.color)}>{analysis.score}%</span>
            <Badge variant={t.variant}>{t.text}</Badge>
            <Badge variant="neutral">Confiança: {analysis.confidence}</Badge>
          </div>
          <div className="mt-2 h-1.5 w-full bg-zinc-800 rounded-full overflow-hidden">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${analysis.score}%` }}
              transition={{ duration: 0.6 }}
              className={cn('h-full rounded-full', t.bar)}
            />
          </div>
          <div className="mt-2 flex items-center gap-2 text-[11px] font-mono text-zinc-500">
            <Fingerprint size={12} /> {analysis.fingerprint}
          </div>
        </div>
      </div>

      {/* Alerta de alta similaridade */}
      {analysis.alert && (
        <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-300">
          <AlertTriangle size={16} className="mt-0.5 shrink-0 text-red-500" />
          <span>{analysis.alert}</span>
        </div>
      )}

      {/* Melhor correspondência */}
      {analysis.best_match ? (
        <CandidateCard c={analysis.best_match} highlight />
      ) : (
        <p className="text-emerald-400/80 text-sm">
          Nenhum candidato acima do limiar. Isso não garante ineditismo — vale uma busca manual.
        </p>
      )}

      {/* Outras fontes relacionadas */}
      {analysis.candidates.filter((c) => c.id !== analysis.best_match?.id).length > 0 && (
        <div>
          <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-500 mb-2">
            Outras fontes relacionadas
          </div>
          <div className="space-y-2">
            {analysis.candidates
              .filter((c) => c.id !== analysis.best_match?.id)
              .slice(0, 4)
              .map((c) => <CandidateCard key={c.id} c={c} />)}
          </div>
        </div>
      )}

      {/* Fontes consultadas + justificativa */}
      <div className="border-t border-zinc-800 pt-4 space-y-2">
        <div className="flex flex-wrap gap-1.5">
          <span className="text-[10px] font-mono uppercase text-zinc-500 mr-1">Fontes consultadas:</span>
          {analysis.sources_consulted.map((s) => <Badge key={s} variant="info">{s}</Badge>)}
        </div>
        <p className="text-xs text-zinc-400 leading-relaxed">{analysis.justificativa}</p>
      </div>
    </div>
  );
}

function CandidateCard({ c, highlight }: { c: ScoredCandidate; highlight?: boolean }) {
  const pct = Math.round((c.similarity || 0) * 100);
  return (
    <div className={cn(
      'rounded-lg border p-3',
      highlight ? 'border-zinc-700 bg-zinc-900/60' : 'border-zinc-800 bg-zinc-900/30'
    )}>
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <a href={c.url} target="_blank" rel="noreferrer"
          className="flex items-center gap-1.5 font-mono text-sm text-blue-400 hover:text-blue-300 break-all">
          {c.id} <ExternalLink size={12} className="shrink-0" />
        </a>
        <div className="flex items-center gap-1.5">
          <Badge variant="neutral">{c.source}</Badge>
          <span className="text-xs font-mono text-zinc-400">{pct}%</span>
        </div>
      </div>

      {c.title && c.title !== c.id && (
        <p className="mt-1 text-xs text-zinc-300">{c.title}</p>
      )}

      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] font-mono text-zinc-500">
        {c.published && <span className="flex items-center gap-1"><Calendar size={11} /> {c.published.slice(0, 10)}</span>}
        {c.cwe?.length > 0 && <span>CWE: {c.cwe.join(', ')}</span>}
        {c.patch_url && (
          <a href={c.patch_url} target="_blank" rel="noreferrer" className="text-emerald-400 hover:text-emerald-300">
            patch
          </a>
        )}
      </div>

      {c.commits?.length > 0 && (
        <div className="mt-2 space-y-0.5">
          {c.commits.slice(0, 3).map((u) => (
            <a key={u} href={u} target="_blank" rel="noreferrer"
              className="flex items-center gap-1 text-[11px] font-mono text-zinc-400 hover:text-zinc-200 break-all">
              <GitCommit size={11} className="shrink-0" /> {u.replace(/^https?:\/\//, '')}
            </a>
          ))}
        </div>
      )}

      {highlight && c.matched_terms?.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {c.matched_terms.slice(0, 10).map((t) => (
            <span key={t} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400">{t}</span>
          ))}
        </div>
      )}
    </div>
  );
}
