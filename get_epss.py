import requests
from typing import TypedDict, Optional
from time import sleep

class EPSSItem(TypedDict):
    cve: str
    epss: str
    percentile: str
    date: str

def get_epss(cve_id: str, retries: int = 5, backoff_factor: float = 1.5) -> Optional[EPSSItem]:
    for attempt in range(retries):
        try:
            print(f"Fetching EPSS data for CVE: {cve_id} (tentativa {attempt+1}/{retries})")
            response = requests.get(f"https://api.first.org/data/v1/epss?cve={cve_id}", timeout=10)
            
            if response.status_code == 429:
                wait_time = backoff_factor * (2 ** attempt)
                print(f"Too Many Requests (429). Retrying in {wait_time:.1f}s...")
                sleep(wait_time)
                continue

            response.raise_for_status()
            data = response.json().get("data", [])
            if not data:
                return None
            return data[0]

        except requests.RequestException as e:
            wait_time = backoff_factor * (2 ** attempt)
            print(f"Erro na request: {e}. Retrying in {wait_time:.1f}s...")
            sleep(wait_time)

    print(f"Falhou após {retries} tentativas para CVE: {cve_id}")
    return None