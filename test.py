from functions import get_all_vulnerabilities_paginated

# Página 1 (primeiros 20 registros mais críticos)
docs_page1 = get_all_vulnerabilities_paginated(page=1)

# Página 2 (próximos 20 registros)
docs_page2 = get_all_vulnerabilities_paginated(page=2)

print(docs_page1)