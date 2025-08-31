from get_epss import get_epss
from get_cve import get_cve
from time import sleep
from db import vulnerabilities_collection

def enchance_data():
    cve_ids = vulnerabilities_collection.distinct("cve_id", {"cve_id": {"$ne": None}})
    print(cve_ids)
    total_cves = len(cve_ids)
    for index, cve_id in enumerate(cve_ids, start=1):
        if cve_id is not None:
            cve_data = get_cve(cve_id)
            epss_data = get_epss(cve_id)
            print(f"Processing {index}/{total_cves}: {cve_id}")
            sleep(2)
            vulnerabilities_collection.update_many(
                {"cve_id": cve_id},
                {"$set": {
                    "cvss": cve_data.get("baseScore"),
                    "epss": epss_data.get("epss")
                }}
            )
