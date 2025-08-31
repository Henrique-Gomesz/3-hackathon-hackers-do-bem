import requests
from typing import TypedDict, Optional


class EPSSItem(TypedDict):
    cve: str
    epss: str
    percentile: str
    date: str

def get_epss(cve_id: str) -> Optional[EPSSItem]:
    try:
        print("Fetching EPSS data for CVE:", cve_id)
        response = requests.get(f"https://api.first.org/data/v1/epss?cve={cve_id}")
        response.raise_for_status()
        data = response.json().get("data", [])
        if not data:
            return None
        
        return data[0]
    except requests.RequestException as e:
        print(f"An error occurred while fetching EPSS data: {e}")
        return None
