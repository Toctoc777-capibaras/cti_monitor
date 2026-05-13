"""
CTI Monitor — Cyber Threat Intelligence Feed Monitor
=====================================================
Monitora fontes de ameaças em busca de mudanças e termos críticos.

Dependências:
    pip install requests pandas openpyxl beautifulsoup4 pyyaml
"""

import hashlib
import json
import logging
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

import requests
import yaml
from bs4 import BeautifulSoup
import pandas as pd


# ---------------------------------------------------------------------------
# Configuração de logging estruturado
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.FileHandler("cti_monitor.log", encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("cti_monitor")


# ---------------------------------------------------------------------------
# Carregamento de configuração externa
# ---------------------------------------------------------------------------
CONFIG_PATH = Path("config.yaml")
DEFAULT_CONFIG: dict = {
    "planilha_fontes": "fontes_cti.xlsx",
    "arquivo_cache": "hash_cache.json",
    "palavras_chave": ["RCE", "Critical", "Zero-day", "Windows Server", "Linux Kernel"],
    "dominios_permitidos": [],          # vazio = permite qualquer domínio público
    "max_workers": 5,                   # threads simultâneas
    "timeout_segundos": 15,
    "max_bytes_resposta": 5_242_880,    # 5 MB
    "delay_min": 1.0,                   # rate limiting — segundos mínimos entre requests
    "delay_max": 3.0,
    "max_tentativas": 3,                # tentativas com backoff exponencial
}


def carregar_config() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            user_cfg = yaml.safe_load(f) or {}
        return {**DEFAULT_CONFIG, **user_cfg}
    log.warning("config.yaml não encontrado — usando configuração padrão.")
    return DEFAULT_CONFIG.copy()


# ---------------------------------------------------------------------------
# Cache (JSON — sem injeção via vírgulas)
# ---------------------------------------------------------------------------
def carregar_hashes(caminho: Path) -> dict[str, str]:
    try:
        with open(caminho, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except FileNotFoundError:
        pass
    except json.JSONDecodeError:
        log.error("Cache corrompido em '%s' — iniciando do zero.", caminho)
    return {}


def salvar_hashes(caminho: Path, hashes: dict[str, str]) -> None:
    try:
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump(hashes, f, indent=2, ensure_ascii=False)
    except OSError as e:
        log.error("Falha ao salvar cache: %s", e)


# ---------------------------------------------------------------------------
# Validação de URL (mitiga SSRF)
# ---------------------------------------------------------------------------
BLOQUEIOS_SSRF = [
    "localhost", "127.", "0.0.0.0", "::1",
    "169.254.",          # link-local / metadata AWS/GCP/Azure
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
]


def url_valida(url: str, dominios_permitidos: list[str]) -> bool:
    try:
        parsed = urlparse(url.strip())
    except Exception:
        return False

    if parsed.scheme not in {"http", "https"}:
        log.warning("Esquema não permitido '%s' em: %s", parsed.scheme, url)
        return False

    host = parsed.netloc.lower().split(":")[0]

    for bloco in BLOQUEIOS_SSRF:
        if host == bloco or host.startswith(bloco):
            log.warning("URL bloqueada por proteção SSRF: %s", url)
            return False

    if dominios_permitidos and host not in dominios_permitidos:
        log.warning("Domínio '%s' não está na allowlist.", host)
        return False

    return True


# ---------------------------------------------------------------------------
# HTTP — request com backoff exponencial e limite de payload
# ---------------------------------------------------------------------------
def fazer_request(
    url: str,
    cfg: dict,
) -> str | None:
    headers = {
        "User-Agent": "CTI-Monitor/2.0 (security research; +https://seu-org.com/bot)",
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
    }

    for tentativa in range(1, cfg["max_tentativas"] + 1):
        try:
            with requests.get(
                url,
                headers=headers,
                timeout=cfg["timeout_segundos"],
                stream=True,
                verify=True,                    # nunca desabilitar verificação TLS
                allow_redirects=True,
            ) as resp:
                if resp.status_code != 200:
                    log.info("HTTP %s em %s", resp.status_code, url)
                    return None

                conteudo = resp.raw.read(
                    cfg["max_bytes_resposta"],
                    decode_content=True,
                )
                return conteudo.decode("utf-8", errors="replace")

        except requests.exceptions.SSLError:
            log.error("Erro de certificado TLS em: %s", url)
            return None
        except requests.exceptions.ConnectionError as e:
            log.warning("[tentativa %d/%d] Conexão falhou em %s: %s",
                        tentativa, cfg["max_tentativas"], url, e)
        except requests.exceptions.Timeout:
            log.warning("[tentativa %d/%d] Timeout em %s",
                        tentativa, cfg["max_tentativas"], url)
        except requests.exceptions.RequestException as e:
            log.error("Erro inesperado ao acessar %s: %s", url, e)
            return None

        if tentativa < cfg["max_tentativas"]:
            espera = (2 ** tentativa) + random.uniform(0, 1)
            log.info("Aguardando %.1fs antes de nova tentativa...", espera)
            time.sleep(espera)

    return None


# ---------------------------------------------------------------------------
# Processamento de uma única URL
# ---------------------------------------------------------------------------
def processar_url(
    url: str,
    cache: dict[str, str],
    cfg: dict,
) -> dict | None:
    """
    Retorna um dicionário com o resultado ou None se não houver alteração.
    """
    time.sleep(random.uniform(cfg["delay_min"], cfg["delay_max"]))

    conteudo = fazer_request(url, cfg)
    if conteudo is None:
        return None

    hash_atual = hashlib.sha256(conteudo.encode("utf-8", errors="replace")).hexdigest()

    if cache.get(url) == hash_atual:
        log.info("Sem novidades: %s", url)
        return None

    log.info("Alteração detectada: %s", url)

    soup = BeautifulSoup(conteudo, "html.parser")
    texto = soup.get_text(separator=" ").lower()
    encontrados = [p for p in cfg["palavras_chave"] if p.lower() in texto]

    return {
        "url": url,
        "hash": hash_atual,
        "termos_encontrados": encontrados,
    }


# ---------------------------------------------------------------------------
# Notificação (extensível)
# ---------------------------------------------------------------------------
def notificar(resultado: dict) -> None:
    url = resultado["url"]
    termos = resultado["termos_encontrados"]

    if termos:
        log.warning(
            "[ALERTA] Termos críticos em %s → %s",
            url, ", ".join(termos),
        )
    else:
        log.info("[MUDANÇA] Conteúdo alterado sem termos críticos: %s", url)

    # Para integrar notificações externas, implemente aqui:
    #   _enviar_telegram(resultado)
    #   _enviar_discord(resultado)
    #   _enviar_email(resultado)


# ---------------------------------------------------------------------------
# Orquestrador principal
# ---------------------------------------------------------------------------
def monitorar_vulnerabilidades() -> None:
    cfg = carregar_config()

    planilha = Path(cfg["planilha_fontes"])
    try:
        df = pd.read_excel(planilha, dtype=str)
        urls_raw: list[str] = df["URL"].dropna().tolist()
    except FileNotFoundError:
        log.critical("Planilha não encontrada: %s", planilha)
        return
    except KeyError:
        log.critical("Coluna 'URL' não encontrada na planilha.")
        return
    except Exception as e:
        log.critical("Erro ao ler planilha: %s", e)
        return

    # Validar URLs antes de qualquer request
    dominios = [d.lower() for d in cfg["dominios_permitidos"]]
    urls = [u for u in urls_raw if url_valida(u, dominios)]

    ignoradas = len(urls_raw) - len(urls)
    if ignoradas:
        log.warning("%d URL(s) ignoradas por falha na validação.", ignoradas)

    if not urls:
        log.error("Nenhuma URL válida para monitorar.")
        return

    cache_path = Path(cfg["arquivo_cache"])
    cache = carregar_hashes(cache_path)

    log.info("Iniciando monitoramento de %d fontes (workers=%d)...",
             len(urls), cfg["max_workers"])

    atualizacoes: dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=cfg["max_workers"]) as executor:
        futuros = {
            executor.submit(processar_url, url, cache, cfg): url
            for url in urls
        }

        for futuro in as_completed(futuros):
            url = futuros[futuro]
            try:
                resultado = futuro.result()
            except Exception as e:
                log.error("Erro inesperado ao processar %s: %s", url, e)
                continue

            if resultado:
                atualizacoes[resultado["url"]] = resultado["hash"]
                notificar(resultado)

    if atualizacoes:
        cache.update(atualizacoes)
        salvar_hashes(cache_path, cache)
        log.info("Cache atualizado com %d entrada(s).", len(atualizacoes))

    log.info("Monitoramento concluído.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    monitorar_vulnerabilidades()