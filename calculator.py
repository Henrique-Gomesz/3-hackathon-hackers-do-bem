from __future__ import annotations
import os
import sys
import json
from typing import Any, Dict, List, Optional
from bson import ObjectId

from db import vulnerabilities_collection as DEFAULT_COLLECTION

from calculator_helper import (
    compute_scores_and_clusters_free,
    date_score_months,
)


def _as_object_id(_id: Any) -> ObjectId:
    if isinstance(_id, ObjectId):
        return _id
    if isinstance(_id, dict) and "$oid" in _id:
        return ObjectId(str(_id["$oid"]))
    return ObjectId(str(_id))


def _clamp01_to_010(x: Any) -> float:
    try:
        v = float(x)
    except Exception:
        v = 0.0
    if v < 0:
        v = 0.0
    if v > 1:
        if v <= 10:
            return v
        return 10.0
    return v * 10.0


def _clamp_010(x: Any) -> float:
    try:
        v = float(x)
    except Exception:
        v = 0.0
    if v < 0:
        return 0.0
    if v > 10:
        return 10.0
    return v


def normalize_item(it: Dict[str, Any]) -> Dict[str, Any]:
    o = dict(it)
    if "epss" in o:
        o["epss"] = _clamp01_to_010(o.get("epss"))
    if "cvss" in o and "cve" not in o:
        o["cve"] = _clamp_010(o.get("cvss"))
    else:
        o["cve"] = _clamp_010(o.get("cve", 0))
    o["companyCriticality"] = _clamp_010(o.get("companyCriticality", 0))
    o["date_norm"] = date_score_months(o.get("date"), horizon_months=60, mode="exp", k=3.0)
    return o


def weights_to_params(weights: Dict[str, float]) -> Dict[str, Any]:
    fields = {}
    for k, w in (weights or {}).items():
        try:
            fields[k] = {"weight": float(w)}
        except Exception:
            fields[k] = {"weight": 1.0}
    return {"fields": fields}


def batch_score_and_update(
    *,
    collection=None,
    weights: Dict[str, float],
    query: Optional[Dict[str, Any]] = None,
    projection: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    coll = DEFAULT_COLLECTION
    q = query or {}
    proj = projection or {
        "_id": 1,
        "name": 1,
        "date": 1,
        "cve_id": 1,
        "cvss": 1,
        "cve": 1,
        "epss": 1,
        "companyCriticality": 1,
        "tags": 1,
        "environments": 1,
    }
    total = coll.count_documents(q)
    cursor = coll.find(q, proj, no_cursor_timeout=True)
    items_norm: List[Dict[str, Any]] = []
    ids: List[Any] = []
    try:
        for doc in cursor:
            ids.append(doc.get("_id"))
            items_norm.append(normalize_item(doc))
    finally:
        cursor.close()
    if not items_norm:
        return {"updated": 0, "skipped": 0, "total": total, "thresholds_raw": {"t1": 0, "t2": 0, "t3": 0}}
    params = weights_to_params(weights)
    res = compute_scores_and_clusters_free(items_norm, params=params, cut_mode="kmeans")
    by_id: Dict[str, Dict[str, Any]] = {str(it.get("_id")): it for it in res["items"]}
    updated = 0
    skipped = 0
    for _id in ids:
        it = by_id.get(str(_id))
        if not it:
            skipped += 1
            continue
        base_score = float(it.get("_raw_score", 0.0))
        priority_class = str(it.get("_class", "media"))
        coll.update_one({"_id": _id}, {"$set": {"base_score": base_score, "priority_class": priority_class}})
        updated += 1
    return {"updated": updated, "skipped": skipped, "total": total, "thresholds_raw": res.get("thresholds_raw")}


def score_and_update(
    doc: Dict[str, Any],
    params: Dict[str, Any],
    *,
    collection=None,
    sample_size: int = 1000,
) -> Dict[str, Any]:
    coll = collection or DEFAULT_COLLECTION

    if "_id" not in doc:
        raise ValueError("Documento precisa conter _id para atualizar no Mongo.")
    oid = _as_object_id(doc["_id"])

    sample: List[Dict[str, Any]] = list(coll.find({}, limit=sample_size))
    found = any(str(x.get("_id")) == str(oid) for x in sample)
    if not found:
        sample.append(doc)

    items_norm = [normalize_item(x) for x in sample]

    res = compute_scores_and_clusters_free(
        items_norm,
        params=params,
        cut_mode="kmeans",
    )

    target = None
    for r in res["items"]:
        if str(r.get("_id")) == str(oid):
            target = r
            break
    if target is None:
        for r in res["items"]:
            if all(r.get(k) == doc.get(k) for k in ("name", "date", "cve_id")):
                target = r
                break
    if target is None:
        target = res["items"][0]

    base_score = float(target.get("_raw_score", 0.0))
    priority_class = str(target.get("_class", "media"))

    update = {"$set": {"base_score": base_score, "priority_class": priority_class}}
    coll.update_one({"_id": oid}, update)

    return {
        "_id": str(oid),
        "base_score": base_score,
        "priority_class": priority_class,
        "thresholds_raw": res.get("thresholds_raw"),
    }


if __name__ == "__main__":
    data = sys.stdin.read().strip()
    if not data:
        print("Passe o DOC JSON no stdin. Exemplo: cat doc.json | python calculator.py")
        sys.exit(1)

    try:
        payload = json.loads(data)
    except Exception as e:
        print(f"JSON inválido: {e}")
        sys.exit(2)

    if isinstance(payload, dict) and "weights" in payload and "doc" not in payload:
        out = batch_score_and_update(
            collection=DEFAULT_COLLECTION,
            weights=payload["weights"],
            query=payload.get("query"),
            projection=payload.get("projection"),
        )
        print(json.dumps(out, ensure_ascii=False, indent=2))
        sys.exit(0)

    if isinstance(payload, dict) and "doc" in payload and "params" in payload:
        doc = payload["doc"]
        params = payload["params"]
    else:
        print("Use um JSON com chaves 'doc' e 'params'.")
        sys.exit(3)

    try:
        out = score_and_update(doc, params, collection=DEFAULT_COLLECTION)
        print(json.dumps(out, ensure_ascii=False, indent=2))
    except Exception as e:
        print(f"Erro: {e}")
        sys.exit(4)