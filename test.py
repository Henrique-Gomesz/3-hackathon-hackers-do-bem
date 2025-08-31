from functions import get_vulnerabilities_filtered

docs = get_vulnerabilities_filtered(
    priority_class=["alta", "media"],
)
print(docs)