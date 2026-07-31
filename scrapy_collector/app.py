"""
Microserviço Scrapy (OPCIONAL) do módulo Anti-Duplicata.

Cobre as fontes que NÃO têm API boa (só HTML): HackerOne Hacktivity público,
Bugcrowd, blogs técnicos. O coletor principal (server_anti_duplicata.mjs) já
resolve CVE/NVD, GitHub Advisories e OSV via APIs oficiais — que são bem mais
confiáveis. Este serviço é o "extra" para o resto.

Contrato (o que o coletor Node espera):
    GET /?q=<termos>  ->  { "candidates": [ {
        "id": str, "source": str, "title": str, "description": str,
        "url": str, "published": str|null, "cwe": [str],
        "commits": [str], "patch_url": str|null, "references": [str]
    } ] }

Como ligar no app principal: defina a env var no deploy do Cyber Hunter Lab:
    SCRAPY_COLLECTOR_URL=http://localhost:8071
e rode este serviço:  python app.py

HONESTIDADE: seletores/endpoints de HTML MUDAM com frequência e vários desses
sites têm anti-bot. Trate como best-effort: se um spider quebrar, ele retorna
lista vazia e o coletor principal segue com as APIs. Valide no SEU ambiente
(aqui no sandbox de dev não há rede pra testar de verdade).
"""
import json
from flask import Flask, request, jsonify
from scrapy.crawler import CrawlerProcess
from scrapy import signals
from spiders.disclosures import DisclosureSpider

app = Flask(__name__)


def run_spider(query: str) -> list:
    """Roda o spider uma vez e coleta os itens em memória."""
    results = []

    def collect(item, response, spider):
        results.append(dict(item))

    process = CrawlerProcess(settings={
        "LOG_ENABLED": False,
        "USER_AGENT": "cyber-hunter-lab-anti-duplicata (+respeita robots.txt)",
        "ROBOTSTXT_OBEY": True,
        "DOWNLOAD_TIMEOUT": 12,
        "CONCURRENT_REQUESTS": 4,
        # cortesia: não martelar os sites
        "DOWNLOAD_DELAY": 0.5,
        "AUTOTHROTTLE_ENABLED": True,
    })

    crawler = process.create_crawler(DisclosureSpider)
    crawler.signals.connect(collect, signal=signals.item_scraped)
    process.crawl(crawler, query=query)
    process.start()  # bloqueia até terminar
    return results


@app.get("/")
def collect_endpoint():
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify({"candidates": []})
    try:
        candidates = run_spider(q)
    except Exception as e:  # best-effort: nunca derruba o coletor principal
        return jsonify({"candidates": [], "error": str(e)}), 200
    return jsonify({"candidates": candidates})


@app.get("/health")
def health():
    return jsonify({"ok": True})


if __name__ == "__main__":
    # Porta separada do app principal (3000). Ajuste se precisar.
    app.run(host="0.0.0.0", port=8071)
