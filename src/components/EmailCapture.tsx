import React, { useState } from 'react';
import { Mail, CheckCircle2 } from 'lucide-react';

export const EmailCapture = () => {
  const [email, setEmail] = useState('');
  const [status, setStatus] = useState<'idle' | 'sending' | 'done' | 'error'>('idle');

  const submit = async () => {
    if (!email.trim()) return;
    setStatus('sending');
    try {
      const r = await fetch('/api/leads', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim() }),
      });
      setStatus(r.ok ? 'done' : 'error');
    } catch {
      setStatus('error');
    }
  };

  if (status === 'done') {
    return (
      <div className="flex items-center gap-2 text-emerald-400 text-xs font-mono px-1">
        <CheckCircle2 size={14} /> Anotado! Avisamos você por lá.
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2 w-full">
      <div className="flex items-center gap-2 px-1">
        <Mail size={14} className="text-zinc-500" />
        <label className="text-[11px] font-mono uppercase tracking-widest text-zinc-500 italic opacity-70">
          Quer saber de novidades e descontos? Deixa seu e-mail
        </label>
      </div>
      <div className="flex gap-2">
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="voce@email.com"
          className="flex-1 h-10 bg-[#1a1a1a] border border-zinc-800 rounded-lg px-3 font-mono text-xs text-zinc-300 focus:outline-none focus:border-zinc-600"
        />
        <button
          onClick={submit}
          disabled={status === 'sending' || !email.trim()}
          className="px-4 rounded-lg bg-emerald-700 hover:bg-emerald-600 disabled:opacity-40 text-xs font-mono text-white"
        >
          {status === 'sending' ? 'Enviando...' : 'Entrar na lista'}
        </button>
      </div>
      {status === 'error' && (
        <p className="text-[11px] text-red-400 px-1">Não consegui salvar agora, tenta de novo.</p>
      )}
    </div>
  );
};
