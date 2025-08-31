

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