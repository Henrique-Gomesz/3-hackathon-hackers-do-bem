import requests
from typing import TypedDict, List, Literal, Optional
import time

class CvssData(TypedDict):
    version: str
    vectorString: str
    baseScore: float
    baseSeverity: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    attackVector: Literal["NETWORK", "ADJACENT", "LOCAL", "PHYSICAL"]
    attackComplexity: Literal["LOW", "HIGH"]
    privilegesRequired: Literal["NONE", "LOW", "HIGH"]
    userInteraction: Literal["NONE", "REQUIRED"]
    scope: Literal["UNCHANGED", "CHANGED"]
    confidentialityImpact: Literal["NONE", "LOW", "HIGH"]
    integrityImpact: Literal["NONE", "LOW", "HIGH"]
    availabilityImpact: Literal["NONE", "LOW", "HIGH"]

def get_cve(cve_id: str, max_retries: int = 5, backoff_factor: float = 1.5) -> Optional[CvssData]:
    retries = 0
    while retries < max_retries:
        try:
            print("Fetching CVE data for CVE:", cve_id)
            response = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")
            
            if response.status_code == 429:
                retries += 1
                wait_time = backoff_factor ** retries
                print(f"Rate limit hit. Retrying in {wait_time:.1f} seconds... (Attempt {retries}/{max_retries})")
                time.sleep(wait_time)
                continue

            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return None
            
            metrics = vulnerabilities[0]["cve"].get("metrics", {})
            cvss_metrics = metrics.get("cvssMetricV31", None)
            
            if cvss_metrics is None:
                cvss_metrics = metrics.get("cvssMetricV2", None)
            
            return cvss_metrics[0]["cvssData"] if cvss_metrics else None
        
        except requests.RequestException as e:
            print(f"An error occurred while fetching CVE data: {e}")
            retries += 1
            wait_time = backoff_factor ** retries
            print(f"Retrying in {wait_time:.1f} seconds... (Attempt {retries}/{max_retries})")
            time.sleep(wait_time)
        except (KeyError, IndexError) as e:
            print(f"An error occurred while processing CVE data: {e}")
            return None
    
    print("Max retries reached. Could not fetch CVE data.")
    return None
