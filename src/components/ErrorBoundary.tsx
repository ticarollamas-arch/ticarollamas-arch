import React from 'react';

interface State {
  hasError: boolean;
  message: string;
}

/**
 * Evita a "tela preta": se qualquer componente quebrar durante a
 * renderização, mostra o motivo na tela em vez de sumir com tudo.
 */
export class ErrorBoundary extends React.Component<{ children: React.ReactNode }, State> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, message: '' };
  }

  static getDerivedStateFromError(error: any): State {
    return { hasError: true, message: error?.message || String(error) };
  }

  render() {
    if (!this.state.hasError) return this.props.children;

    return (
      <div className="min-h-screen bg-[#0d0d0d] flex items-center justify-center p-4">
        <div className="w-full max-w-md bg-[#121212] border border-zinc-800 rounded-2xl p-8 space-y-4 text-center">
          <h1 className="text-lg font-bold text-white">Algo quebrou ao carregar</h1>
          <p className="text-xs text-zinc-500 font-mono break-words bg-black/40 p-3 rounded-lg">
            {this.state.message}
          </p>
          <button
            onClick={() => { localStorage.clear(); sessionStorage.clear(); window.location.href = '/'; }}
            className="w-full bg-[#1a1a1a] hover:bg-zinc-800 border border-zinc-800 rounded-xl py-3 text-[11px] font-mono uppercase tracking-widest text-zinc-300"
          >
            Limpar dados e recomeçar
          </button>
        </div>
      </div>
    );
  }
}
