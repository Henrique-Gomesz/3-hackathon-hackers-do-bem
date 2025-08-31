import requests
from typing import TypedDict, List, Literal, Optional

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

def get_cve(cve_id: str) -> Optional[CvssData]:
    try:
        print("Fetching CVE data for CVE:", cve_id)
        response = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx and 5xx)
        data = response.json()
        
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None
        
        metrics = vulnerabilities[0]["cve"].get("metrics", {})
        cvss_metrics = metrics.get("cvssMetricV31", None)
        
        if cvss_metrics is None:
            cvss_metrics = metrics.get("cvssMetricV2", None)
        
        return cvss_metrics[0]["cvssData"]
    except requests.RequestException as e:
        print(f"An error occurred while fetching CVE data: {e}")
        return None
    except (KeyError, IndexError) as e:
        print(f"An error occurred while processing CVE data: {e}")
        return None