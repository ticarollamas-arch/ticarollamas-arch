"""
Spider de divulgações públicas para o módulo Anti-Duplicata.

Fontes cobertas aqui (só-HTML / API não-oficial):
  1. HackerOne Hacktivity (disclosures públicas) — via GraphQL público.
  2. Blogs/aggregadores de segurança — exemplo com busca no cvedetails.

IMPORTANTE (leia antes de confiar):
  - Endpoints e esquemas GraphQL do HackerOne NÃO são contratados publicamente
    e mudam sem aviso. Se parar de funcionar, ajuste a query/os campos.
  - Respeite os Termos de Uso e o robots.txt de cada site. Isto lê apenas
    conteúdo JÁ PÚBLICO (disclosures divulgadas), para triagem de duplicata.
  - Cada bloco é isolado em try/except: se uma fonte quebrar, as outras seguem
    e o pior caso é lista vazia (o coletor principal continua com as APIs).
"""
import json
import scrapy


class DisclosureSpider(scrapy.Spider):
    name = "disclosures"

    def __init__(self, query: str = "", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.query = query

    def start_requests(self):
        # --- Fonte 1: HackerOne Hacktivity (GraphQL público) ---
        h1_payload = {
            "operationName": "HacktivitySearchQuery",
            "variables": {
                "queryString": self.query,
                "size": 10,
                "from": 0,
                "sort": [{"field": "latest_disclosable_activity_at", "direction": "DESC"}],
                "product_area": "hacktivity",
                "product_feature": "overview",
            },
            # A query real do H1 é longa; mantemos mínima e tolerante a erro.
            "query": "query HacktivitySearchQuery($queryString: String!, $size: Int, $from: Int) {"
                     " search(index: CompleteHacktivityReportIndex, query_string: $queryString, first: $size, from: $from) {"
                     " nodes { ... on HacktivityDocument { _id report { title url disclosed_at }"
                     " severity_rating cve_ids } } } }",
        }
        yield scrapy.Request(
            url="https://hackerone.com/graphql",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps(h1_payload),
            callback=self.parse_hackerone,
            errback=self.on_error,
            dont_filter=True,
        )

        # --- Fonte 2: cvedetails (HTML, exemplo de blog/aggregador) ---
        yield scrapy.Request(
            url=f"https://www.cvedetails.com/google-search-results.php?q={scrapy.utils.python.to_unicode(self.query)}",
            callback=self.parse_cvedetails,
            errback=self.on_error,
            dont_filter=True,
        )

    def parse_hackerone(self, response):
        try:
            data = json.loads(response.text)
        except Exception:
            return
        nodes = (data.get("data", {}) or {}).get("search", {}).get("nodes", []) or []
        for n in nodes:
            report = n.get("report") or {}
            url = report.get("url")
            if not url:
                continue
            yield {
                "id": n.get("_id") or url,
                "source": "HackerOne",
                "title": report.get("title") or "HackerOne disclosure",
                "description": report.get("title") or "",
                "url": url,
                "published": report.get("disclosed_at"),
                "cwe": [],
                "commits": [],
                "patch_url": None,
                "references": [url],
            }

    def parse_cvedetails(self, response):
        # Seletor genérico e defensivo — HTML muda, então extrai o que der.
        for row in response.css("a[href*='/cve/CVE-']")[:10]:
            href = row.attrib.get("href", "")
            title = (row.css("::text").get() or "").strip()
            if not href:
                continue
            full = response.urljoin(href)
            cve_id = href.split("/cve/")[-1].split("/")[0] if "/cve/" in href else full
            yield {
                "id": cve_id,
                "source": "cvedetails",
                "title": title or cve_id,
                "description": title,
                "url": full,
                "published": None,
                "cwe": [],
                "commits": [],
                "patch_url": None,
                "references": [full],
            }

    def on_error(self, failure):
        # Best-effort: loga e ignora (não derruba as outras fontes).
        self.logger.warning(f"fonte falhou: {failure.value}")
