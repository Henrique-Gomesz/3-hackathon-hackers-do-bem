

from typing import Any, Dict, List, Optional
from bson import ObjectId
from db import vulnerabilities_collection
from jira_api import gen_title_desc, create_issue


def _to_oid(x: Any) -> ObjectId:
    if isinstance(x, ObjectId):
        return x
    if isinstance(x, dict) and "$oid" in x:
        return ObjectId(str(x["$oid"]))
    return ObjectId(str(x))


def _extract_for_llm(doc: Dict[str, Any]) -> Dict[str, Any]:
    keys = [
        "name",
        "description",
        "companyCriticality",
        "date",
        "cve_id",
        "cvss",
        "epss",
        "family",
        "environments",
        "tags",
    ]
    return {k: doc.get(k) for k in keys if k in doc}


def create_issue_from_mongo_id(mongo_id: Any, project_key: str = "MFLP", issue_type: str = "Task") -> Dict[str, Any]:
    oid = _to_oid(mongo_id)
    doc = vulnerabilities_collection.find_one({"_id": oid})
    if not doc:
        return {"error": "not_found", "_id": str(oid)}
    obj = _extract_for_llm(doc)
    titulo, descricao = gen_title_desc(obj)
    jira = create_issue(project_key, titulo, descricao, issue_type)
    return {"_id": str(oid), "titulo": titulo, "descricao": descricao, "jira": jira}


def create_issues_for_ids(ids: List[Any], project_key: str = "MFLP", issue_type: str = "Task") -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for x in ids:
        try:
            out.append(create_issue_from_mongo_id(x, project_key=project_key, issue_type=issue_type))
        except Exception as e:
            out.append({"_id": str(x), "error": str(e)})
    return out



from datetime import datetime


def _parse_date_any(s: Optional[str]):
    if not s:
        return None
    s = str(s).strip()
    fmts = ("%d/%m/%Y", "%Y-%m-%d", "%Y/%m/%d", "%Y-%m", "%Y/%m", "%Y")
    for fmt in fmts:
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            continue
    return None


def get_vulnerabilities_filtered(
    *,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    priority_class: Optional[List[str] | str] = None,
    ambientes: Optional[List[str] | str] = None,
    tipos: Optional[List[str] | str] = None,
    projection: Optional[Dict[str, int]] = None,
    limit: int = 1000,
    skip: int = 0,
    sort_by: str = "base_score",
    sort_dir: int = -1,
) -> List[Dict[str, Any]]:
    q = {"$and": []}
    if priority_class:
        pcs = priority_class if isinstance(priority_class, list) else [priority_class]
        q["$and"].append({"priority_class": {"$in": pcs}})
    ambs = None
    if ambientes:
        ambs = ambientes if isinstance(ambientes, list) else [ambientes]
        ambs = [a.upper() for a in ambs]
        q["$and"].append({
            "$or": [
                {"environments": {"$in": ambs}},
                {"environments.value": {"$in": ambs}},
                {"tags": {"$elemMatch": {"category": "AMBIENTE", "value": {"$in": ambs}}}}
            ]
        })
    if tipos:
        tps = tipos if isinstance(tipos, list) else [tipos]
        tps = [t.upper() for t in tps]
        q["$and"].append({
            "$or": [
                {"tags": {"$elemMatch": {"category": "TIPO", "value": {"$in": tps}}}}
            ]
        })
    if not q["$and"]:
        q = {}
    proj = projection or {
        "_id": 1,
        "name": 1,
        "date": 1,
        "cve_id": 1,
        "cvss": 1,
        "cve": 1,
        "epss": 1,
        "companyCriticality": 1,
        "base_score": 1,
        "priority_class": 1,
        "environments": 1,
        "tags": 1,
    }
    cur = vulnerabilities_collection.find(q, proj).sort(sort_by, sort_dir).skip(max(0, int(skip))).limit(max(0, int(limit)))
    docs = list(cur)
    if start_date or end_date:
        sd = _parse_date_any(start_date) if start_date else None
        ed = _parse_date_any(end_date) if end_date else None
        out = []
        for d in docs:
            dt = _parse_date_any(d.get("date"))
            if dt is None:
                continue
            if sd and dt < sd:
                continue
            if ed and dt > ed:
                continue
            out.append(d)
        docs = out
    return docs