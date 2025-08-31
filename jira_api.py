LM_STUDIO_URL = "http://localhost:1234/v1/chat/completions"
LM_MODEL_ID = "llama-3-8b-gpt-4o-ru1.0"
SYSTEM_PROMPT = (
    "Voce é um PO senior da compania, você recebe um objeto JSON e deve gerar APENAS um JSON com as chaves 'titulo' e 'descricao' para abrir um card no Jira. "
    "Regras: não explique causas técnicas; se houver nulos, use o que existir (inclua name/cve_id no título se ajudar); "
    "seja claro e conciso; devolva somente o JSON final. Voce deve falar apenas o que se Deve fazer e não fazer, nao tire explicacoes da cartola mas diga o que se da a entender nos dados. NAO SEJA GENERICO"
    "Ao final da descricao, pontue duas possiveis solucoes, seja direto e reto nessas possiveis solucoes exemplo : talvez rodando XPTO resolva o problema"
)

def gen_title_desc(obj: dict) -> tuple[str, str]:
    payload = {
        "model": LM_MODEL_ID,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "Objeto recebido:\n" + json.dumps(obj, ensure_ascii=False)}
        ],
        "temperature": 0.4,
        "top_p": 0.9,
        "max_tokens": 256,
        "stream": False
    }
    resp = requests.post(LM_STUDIO_URL, headers={"Content-Type": "application/json"}, json=payload, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    content = data["choices"][0]["message"]["content"]
    s, e = content.find("{"), content.rfind("}")
    raw = content[s:e+1] if s != -1 and e != -1 else "{\"titulo\":\"\",\"descricao\":\"\"}"
    try:
        jd = json.loads(raw)
    except Exception:
        jd = {"titulo": "", "descricao": content.strip()[:200]}
    titulo = jd.get("titulo") or "Melhoria"
    descricao = jd.get("descricao") or "Sem descrição"
    return titulo, descricao



import json
import sys
import requests
from requests.auth import HTTPBasicAuth

def resolve_issue_type(project_key: str, desired: str) -> str:
    return desired

JIRA_URL = "https://hackathon-do-bem.atlassian.net"
JIRA_EMAIL = "tr19496@gmail.com"
JIRA_TOKEN = "ATATT3xFfGF0GRmD59MnyUcv-5i0H7m3jQAxT_5iBZVKweIGIPsetu6Q_nqtHeEfz71Dsf0iHDVRZ6o1dIy-tLCdGAopdwpA_YQLMUkpLqMXdMsoL-4NoQ-RUZULuijamMa_vS7JKHPRxjqCcVoyKNdDk3isUMiZE881dW17fQpG7Hoqpo_1ytM=AFE61DBC"

def create_issue(project_key, summary, description, issue_type="Task"):
    adf_description = {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": description}
                ]
            }
        ]
    }
    r = requests.post(
        f"{JIRA_URL.rstrip('/')}/rest/api/3/issue",
        auth=HTTPBasicAuth(JIRA_EMAIL, JIRA_TOKEN),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        json={
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "description": adf_description,
                "issuetype": {"name": issue_type}
            }
        },
        timeout=30,
    )
    if r.status_code not in (200, 201):
        print(r.text, file=sys.stderr)
        r.raise_for_status()
    return r.json()

if __name__ == "__main__":
    try:
        if not sys.stdin.isatty():
            obj = json.loads(sys.stdin.read())
        else:
            obj = {"name": "openssl", "description": "Falha genérica", "companyCriticality": 5}
    except Exception:
        obj = {"name": "openssl", "description": "Falha genérica", "companyCriticality": 5}

    titulo, descricao = gen_title_desc(obj)
    issue_type = resolve_issue_type("MFLP", "Task")
    result = create_issue("MFLP", titulo, descricao, issue_type)
    print(json.dumps(result, ensure_ascii=False, indent=2))