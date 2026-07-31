# Módulo Anti-Duplicata — guia de integração

Sistema que, antes de gerar o relatório final, pesquisa se a vulnerabilidade
(ou um padrão muito semelhante) já foi divulgada publicamente. **Nunca afirma
que é duplicata** — só apresenta similaridade + evidências para a triagem do
pesquisador decidir.

## Arquivos

| Arquivo | O que é |
|---|---|
| `src/lib/antiDuplicata.ts` | **Núcleo** (offline): fingerprint, extração de características, similaridade, classificação 🔴/🟡/🟢. Determinístico e testável. |
| `src/lib/antiDuplicata.test.ts` | Testes do núcleo (`tsx src/lib/antiDuplicata.test.ts`). |
| `server_anti_duplicata.mjs` | **Coletor** (backend): consulta CVE/NVD, GitHub Advisories e OSV via **APIs oficiais**. Já ligado no `server.js`. |
| `src/components/OriginalityPanel.tsx` | Painel visual (indicador, score, best match, commits, patch, evidências, alerta). |
| `scrapy_collector/` | Serviço **opcional** em Scrapy p/ fontes só-HTML (HackerOne, Bugcrowd, blogs). |
| `UniversalReportGenerator.tsx` | Ganhou a seção **"5. Análise de Originalidade"** no relatório. |

## Como funciona (fluxo)

1. Achado confirmado → monta um `FindingInput` (use `findingFromReportVuln(v)`).
2. `runAntiDuplicata(finding)` chama `POST /api/anti-duplicata` (coleta no servidor)
   e **pontua no cliente** (transparente).
3. Resultado (`OriginalityAnalysis`) alimenta o `OriginalityPanel` e é anexado
   ao achado como campo `originality` → aparece na seção 5 do relatório.

**Divisão proposital:** a coleta (que precisa de rede) fica no servidor; a
pontuação/decisão fica no cliente, determinística e auditável.

## Plugar no fluxo de análise (exemplo)

```tsx
import { useState } from 'react';
import { OriginalityPanel } from './OriginalityPanel';
import { runAntiDuplicata, findingFromReportVuln } from '../lib/antiDuplicata';
import type { OriginalityAnalysis } from '../lib/antiDuplicata';

function AchadoView({ vuln }: { vuln: any }) {
  const [orig, setOrig] = useState<OriginalityAnalysis | null>(vuln.originality ?? null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const checar = async () => {
    setLoading(true); setErr(null);
    try {
      const finding = findingFromReportVuln(vuln);
      const r = await runAntiDuplicata(finding);
      setOrig(r);
      vuln.originality = r; // anexa p/ o relatório renderizar a seção 5
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  };

  return <OriginalityPanel analysis={orig} loading={loading} error={err} onRun={checar} />;
}
```

## Classificação

- 🔴 **> 90%** — alta probabilidade de duplicata (mostra alerta).
- 🟡 **60–90%** — similaridade média.
- 🟢 **< 60%** — nenhuma correspondência relevante.

Modelo de score (honesto): `0.45·CWE + 0.45·texto + 0.10·(melhor sinal de código)`.
Match só de prosa (NVD) chega ao 🟡 alto; para cravar 🔴 precisa de
**corroboração de código** (função/arquivo/patch batendo — o que vem de
GHSA/OSV/commits), que é justo quando a confiança de duplicata é maior.

## Config (tudo opcional — melhora limites de rate e cobertura)

Variáveis de ambiente no deploy (ou chaves em `settings.json`):

| Var | Para quê |
|---|---|
| `NVD_API_KEY` | NVD: 5→50 req/30s. Pegue grátis em nvd.nist.gov. |
| `GITHUB_TOKEN` | GitHub Advisories: ~60→5000 req/h. |
| `SCRAPY_COLLECTOR_URL` | Liga o serviço Scrapy opcional (ex: `http://localhost:8071`). |

## Serviço Scrapy opcional

```bash
cd scrapy_collector
pip install -r requirements.txt
python app.py           # sobe em :8071
# e no deploy principal: SCRAPY_COLLECTOR_URL=http://localhost:8071
```

Cobre HackerOne/Bugcrowd/blogs (só-HTML). **Best-effort:** seletores e
endpoints de HTML mudam e há anti-bot; se quebrar, retorna vazio e o coletor
principal segue com as APIs. Valide no seu ambiente.

## Limitação conhecida

A coleta precisa de **rede em runtime**. No ambiente onde a ferramenta foi
validada (que já retorna resultado no terminal) isso funciona; num sandbox
sem rede, as fontes retornam erro/vazio e a classificação cai em 🟢 por falta
de candidatos — sem quebrar o fluxo. As APIs usadas: `services.nvd.nist.gov`,
`api.github.com`, `api.osv.dev` (libere na allowlist de egress do deploy, se
houver).
