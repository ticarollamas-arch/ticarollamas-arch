import React, { useRef, useState } from 'react';
import { FolderUp } from 'lucide-react';
import { cn } from '../lib/utils';

interface FolderInputProps {
  onLoaded: (combinedText: string, fileCount: number) => void;
}

// Extensões de código consideradas relevantes. O resto (imagens, binários,
// lockfiles, etc.) é ignorado pra não estourar o tamanho do prompt.
const CODE_EXTS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.py', '.go', '.java', '.rb', '.php',
  '.c', '.cpp', '.h', '.hpp', '.cs', '.rs', '.yaml', '.yml', '.json',
  '.env', '.toml', '.sh', '.sql', '.html', '.css', '.md',
]);

const IGNORE_DIRS = ['node_modules/', '.git/', 'dist/', 'build/', '__pycache__/', '.venv/'];

const MAX_TOTAL_CHARS = 200_000; // limite de segurança pro tamanho do prompt

export const FolderInput = ({ onLoaded }: FolderInputProps) => {
  const inputRef = useRef<HTMLInputElement>(null);
  const [status, setStatus] = useState<string>('');

  const handleFiles = async (fileList: FileList) => {
    const files = Array.from(fileList).filter((f) => {
      const rel = (f as any).webkitRelativePath || f.name;
      if (IGNORE_DIRS.some((d) => rel.includes(d))) return false;
      const dot = f.name.lastIndexOf('.');
      const ext = dot >= 0 ? f.name.slice(dot).toLowerCase() : '';
      return CODE_EXTS.has(ext);
    });

    if (files.length === 0) {
      setStatus('Nenhum arquivo de código reconhecido nessa pasta.');
      return;
    }

    setStatus(`Lendo ${files.length} arquivo(s)...`);

    let combined = '';
    let used = 0;
    let skipped = 0;
    for (const f of files) {
      if (combined.length >= MAX_TOTAL_CHARS) {
        skipped++;
        continue;
      }
      const rel = (f as any).webkitRelativePath || f.name;
      const text = await f.text();
      combined += `\n// ===== ${rel} =====\n${text}\n`;
      used++;
    }

    if (combined.length > MAX_TOTAL_CHARS) {
      combined = combined.slice(0, MAX_TOTAL_CHARS) + '\n// [conteúdo cortado — pasta muito grande para um único envio]';
    }

    const msg = skipped > 0
      ? `${used} arquivo(s) carregado(s), ${skipped} ignorado(s) por limite de tamanho.`
      : `${used} arquivo(s) carregado(s) da pasta.`;
    setStatus(msg);
    onLoaded(combined, used);
  };

  return (
    <div className="flex flex-col gap-2 w-full">
      <button
        type="button"
        onClick={() => inputRef.current?.click()}
        className={cn(
          'flex items-center justify-center gap-2 w-full h-12 rounded-lg border border-dashed border-zinc-700',
          'text-zinc-400 text-sm font-mono hover:border-zinc-500 hover:text-zinc-200 transition-colors'
        )}
      >
        <FolderUp size={16} />
        Anexar pasta de código
      </button>
      <input
        ref={inputRef}
        type="file"
        multiple
        className="hidden"
        onChange={(e) => e.target.files && handleFiles(e.target.files)}
        {...({ webkitdirectory: '', directory: '' } as any)}
      />
      {status && <p className="text-[11px] text-zinc-500 font-mono px-1">{status}</p>}
    </div>
  );
};
