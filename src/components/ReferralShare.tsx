import React, { useEffect, useState } from 'react';
import { Share2, Copy, Check } from 'lucide-react';

function getOrCreateRefCode(): string {
  const key = 'my_ref_code';
  let code = localStorage.getItem(key);
  if (!code) {
    code = Math.random().toString(36).slice(2, 8);
    localStorage.setItem(key, code);
  }
  return code;
}

export const ReferralShare = () => {
  const [link, setLink] = useState('');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const code = getOrCreateRefCode();
    setLink(`${window.location.origin}/?ref=${code}`);
  }, []);

  const copyLink = async () => {
    await navigator.clipboard.writeText(link);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const shareWhatsapp = () => {
    window.open(`https://wa.me/?text=${encodeURIComponent('Testa essa ferramenta de segurança: ' + link)}`, '_blank');
  };

  const shareTwitter = () => {
    window.open(`https://twitter.com/intent/tweet?text=${encodeURIComponent('Testa essa ferramenta de segurança:')}&url=${encodeURIComponent(link)}`, '_blank');
  };

  if (!link) return null;

  return (
    <div className="flex flex-col gap-2 w-full">
      <div className="flex items-center gap-2 px-1">
        <Share2 size={14} className="text-zinc-500" />
        <label className="text-[11px] font-mono uppercase tracking-widest text-zinc-500 italic opacity-70">
          Seu link de indicação
        </label>
      </div>
      <div className="flex gap-2 flex-wrap">
        <button
          onClick={copyLink}
          className="flex items-center gap-2 px-3 h-10 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-xs font-mono text-zinc-200"
        >
          {copied ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
          {copied ? 'Copiado!' : 'Copiar link'}
        </button>
        <button
          onClick={shareWhatsapp}
          className="px-3 h-10 rounded-lg bg-emerald-800 hover:bg-emerald-700 text-xs font-mono text-white"
        >
          WhatsApp
        </button>
        <button
          onClick={shareTwitter}
          className="px-3 h-10 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-xs font-mono text-zinc-200"
        >
          Twitter/X
        </button>
      </div>
    </div>
  );
};
