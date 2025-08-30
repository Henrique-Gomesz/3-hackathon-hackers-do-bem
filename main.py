from get_epss import get_epss
from get_cve import get_cve

cve_id = "CVE-2021-34527"
cve_data = get_cve(cve_id)
epss_data = get_epss(cve_id)

print("CVE Data:", cve_data.get("baseScore"))
print("EPSS Data:", epss_data.get("epss"))

