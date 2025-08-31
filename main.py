from db import vulnerabilities_collection

import json

from calculator import batch_score_and_update, weights_to_params
from calculator_helper import select_top_gravissima

weights = {
    "cve": 1,
    "epss": 2,
    "companyCriticality": 1,
    "date_norm": 1
}

# summary = batch_score_and_update(
#     collection=vulnerabilities_collection,
#     weights=weights
# )

# print(json.dumps(summary, ensure_ascii=False, indent=2))

res = select_top_gravissima(
    collection=vulnerabilities_collection,
    weights=weights,
    limit=2
)

#print(res)

selected_payload = {
    "thresholds_raw": res.get("thresholds_raw"),
    "selected": res.get("selected", [])
}
print (selected_payload)



