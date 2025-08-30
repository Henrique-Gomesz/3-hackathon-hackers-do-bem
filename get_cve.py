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
    response = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")
    data = response.json()
    
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return None
    
    metrics = vulnerabilities[0]["cve"].get("metrics", {})
    cvss_metrics = metrics.get("cvssMetricV31", [])
    
    if not cvss_metrics:
        return None
    
    return cvss_metrics[0]["cvssData"]