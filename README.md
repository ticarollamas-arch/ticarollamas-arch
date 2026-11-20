# Ana Caroline Lamas

**Desenvolvedora Python · Segurança de Aplicações · Agentes e Automação**
Nova Lima, MG – Brasil

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Ana_Caroline_Lamas-0A66C2?logo=linkedin&logoColor=white)](https://linkedin.com/in/ana-caroline-lamas-605152351)
[![Email](https://img.shields.io/badge/Email-acarollamas@gmail.com-EA4335?logo=gmail&logoColor=white)](mailto:acarollamas@gmail.com)
[![Site](https://img.shields.io/badge/Site-cyberhuntlab.com.br-111111)](https://cyberhuntlab.com.br)

---

Construo ferramentas de linha de comando em Python para pesquisa de segurança: reconhecimento passivo, detecção baseada em CWE e pipelines de agentes que explicam o raciocínio por trás de cada achado. Gosto de entender como as coisas são feitas por dentro — engenharia reversa, análise estática e automação.

Fui administradora do **Google Summer of Code 2026** pela organização open source **BRL-CAD**, cuidando de prazos, avaliações e suporte aos contribuidores.

## Projetos em destaque

| Projeto | O que faz | Stack |
|---|---|---|
| [**CWE-Cover-2.0**](https://github.com/ticarollamas-arch/CWE-Cover-2.0) | Motor de reconhecimento passivo para bug bounty (`cwe_discover.py`): exige autorização explícita e arquivo de escopo, aplica regras declarativas por CWE e passa os achados por agentes de mapeamento, falso positivo e impacto antes do relatório. Suíte de testes com pytest. | Python, CLI |
| [**go-traversal-detector**](https://github.com/ticarollamas-arch/go-traversal-detector) | Análise estática que encontra `filepath.Join`/`os.Open` com caminho não confiável em código Go e verifica se existe barreira de contenção antes de apontar o candidato. Não gera PoC — indica onde revisar. | Python |
| [**Engenharia-Reversa**](https://github.com/ticarollamas-arch/Engenharia-Reversa) | Inspeciona pacotes compactados e compilados (zip, tar, apk) com defesas contra ZipSlip e zip bomb, mapeia a arquitetura e publica o conteúdo direto no GitHub. | TypeScript |

## Como eu trabalho

- **Evidência antes de alarme:** uma ferramenta de segurança só é útil se o falso positivo for raro e cada achado vier com o motivo.
- **Escopo e autorização primeiro:** minhas ferramentas recusam rodar sem confirmação de que o alvo é autorizado.
- **Terminal como ambiente principal:** monto, testo e faço deploy pela linha de comando.

## Ferramentas

Python · Go (leitura e análise) · TypeScript · Docker · GitHub Actions · Google Cloud · LLMs e orquestração de agentes · OWASP Top 10 · CWE/CVE · análise estática e *taint analysis*

## Formação

- Data Analysis with Python — freeCodeCamp (2026)
- Google Cloud Skills Boost — trilhas de Vertex AI, MLOps e agentes
- Bootcamps e trilhas de desenvolvimento e segurança (Santander, Google, Anthropic)
