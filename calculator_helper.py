from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

# ==============================
# Data -> score 0..10 (idade em meses)
# ==============================

def date_score_months(
    date_str: Optional[str],
    ref_year: Optional[int] = None,
    ref_month: Optional[int] = None,
    horizon_months: int = 60,
    mode: str = "exp",
    k: float = 3.0,
) -> float:
    """
    Converte uma data em um score 0..10 baseado na idade em meses.
    - 0 ~ recente; 10 ~ muito antigo (satura em ~horizon_months)
    Formatos aceitos: 'DD/MM/YYYY', 'YYYY-MM-DD', 'YYYY/MM/DD', 'YYYY-MM', 'YYYY/MM', 'YYYY'
    """
    if not date_str:
        return 0.0

    def _parse(s: str) -> Optional[Tuple[int, int]]:
        s = s.strip()
        fmts = ("%d/%m/%Y", "%Y-%m-%d", "%Y/%m/%d", "%Y-%m", "%Y/%m", "%Y")
        for fmt in fmts:
            try:
                dt = datetime.strptime(s, fmt)
                return dt.year, (dt.month if "%m" in fmt else 1)
            except Exception:
                continue
        return None

    ym = _parse(str(date_str))
    if ym is None:
        return 0.0

    if ref_year is None or ref_month is None:
        today = datetime.today()
        ref_year, ref_month = today.year, today.month

    y, m = ym
    months = max(0, (ref_year - y) * 12 + (ref_month - m))
    x = months / float(max(1, horizon_months))  # 0..~

    if mode == "linear":
        score = 10.0 * (x if x < 1.0 else 1.0)
    else:  # exp (padrão)
        score = 10.0 * (1.0 - math.exp(-k * x))
    # clamp será resolvido em tempo de execução (a função clamp está definida mais abaixo)
    try:
        return round(clamp(score, 0.0, 10.0), 6)
    except NameError:
        # fallback se clamp ainda não estiver no namespace durante import
        score = max(0.0, min(10.0, score))
        return round(score, 6)


def compute_scores_and_dynamic_classes(
    items: List[Dict[str, Any]],
    *,
    weights: Optional[Dict[str, float]] = None,
    ref_year: Optional[int] = None,
    ref_month: Optional[int] = None,
    horizon_months: int = 60,
    date_mode: str = "exp",
    date_k: float = 3.0,
    q_low: float = 0.01,
    q_high: float = 0.99,
    quantile_cuts: Tuple[float, float, float] = (0.50, 0.80, 0.95),
    ensure_top_frac: Optional[float] = None,
    ensure_min_n: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Dinâmico por base: calcula scores para todos os itens e define cortes
    automaticamente a partir dos QUANTIS da própria base.

    - quantile_cuts: (q1, q2, q3) em [0,1]. Ex.: (0.50, 0.80, 0.95)
      baixa <= t1 < media <= t2 < alta <= t3 < gravissima
    - ensure_top_frac / ensure_min_n: garante que pelo menos uma fração (ou N) do topo
      seja marcado como 'gravissima' mesmo se a distribuição estiver muito achatada.

    Retorna dict com:
      {
        'thresholds': {'t1': float, 't2': float, 't3': float},
        'items': [ { ..., '_score_0_100': float, '_class': str, '_is_critical': bool }, ... ]
      }
    """
    if not items:
        return {'thresholds': {'t1': 0.0, 't2': 0.0, 't3': 0.0}, 'items': []}

    # 1) Reaproveita o pipeline de compute_scores_and_classes para obter _score_0_100
    base = compute_scores_and_classes(
        items,
        weights=weights,
        ref_year=ref_year,
        ref_month=ref_month,
        horizon_months=horizon_months,
        date_mode=date_mode,
        date_k=date_k,
        q_low=q_low,
        q_high=q_high,
        cuts=(25.0, 50.0, 85.0),  # cortes serão recalculados abaixo (dinâmicos)
    )

    scores = [row['_score_0_100'] for row in base]

    # 2) Define cortes dinâmicos pelos quantis da BASE
    q1, q2, q3 = quantile_cuts
    t1 = _percentile(scores, q1)
    t2 = _percentile(scores, q2)
    t3 = _percentile(scores, q3)

    # 3) Classifica conforme cortes dinâmicos
    for row in base:
        s = row['_score_0_100']
        if s <= t1:
            row['_class'] = 'baixa'
        elif s <= t2:
            row['_class'] = 'media'
        elif s <= t3:
            row['_class'] = 'alta'
        else:
            row['_class'] = 'gravissima'
        row['_is_critical'] = (row['_class'] == 'gravissima')

    return {
        'thresholds': {'t1': round(t1, 2), 't2': round(t2, 2), 't3': round(t3, 2)},
        'items': base,
    }


def final_value(item: Dict[str, Any], population: List[Dict[str, Any]], **kwargs) -> Tuple[float, str]:
    """
    Retorna (score_0_100, classe) do item usando cortes dinâmicos
    aprendidos na população. Se o item não estiver na população, ele é
    concatenado temporariamente para cálculo consistente.
    """
    pool = population + [item] if item not in population else population
    result = compute_scores_and_dynamic_classes(pool, **kwargs)
    # encontra o último (se concatenou) ou o matching pelo id/nome
    target = None
    if item not in population:
        target = result['items'][0]  # já está ordenado desc; o item pode não ser o primeiro
        # então vamos procurar pelo objeto que tenha todos os campos iguais (fallback simples)
        for r in result['items']:
            if all(r.get(k) == item.get(k) for k in ('name', 'date', 'cve_id')):
                target = r
                break
        if target is None:
            target = result['items'][-1]
    else:
        for r in result['items']:
            if all(r.get(k) == item.get(k) for k in ('name', 'date', 'cve_id')):
                target = r
                break
        if target is None:
            target = result['items'][0]
    return target['_score_0_100'], target['_class']

# =============================================
# Robust + Clustering (SEM reescalar para 0..100)
# =============================================
from typing import List, Dict, Any, Optional, Tuple
import math

# Assumimos que já existem: to_features_0_10, _percentile, _robust_z_list,
# date_score_months, clamp, _kmeans_1d_thresholds, _degenerate.

# ---- Generic helpers ----
def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def _percentile(values: List[float], q: float) -> float:
    """Percentile without numpy. q in [0,1]."""
    if not values:
        return 0.0
    xs = sorted(values)
    q = clamp(q, 0.0, 1.0)
    idx = q * (len(xs) - 1)
    lo_i = int(math.floor(idx))
    hi_i = int(math.ceil(idx))
    if lo_i == hi_i:
        return xs[lo_i]
    frac = idx - lo_i
    return xs[lo_i] * (1 - frac) + xs[hi_i] * frac


def _robust_z_list(values: List[float], cap: float = 3.0) -> List[float]:
    """Median + MAD robust z, capped in [-cap, cap]."""
    if not values:
        return []
    xs = sorted(values)
    n = len(xs)
    if n % 2:
        med = xs[n//2]
    else:
        med = 0.5 * (xs[n//2 - 1] + xs[n//2])
    mad = _percentile([abs(v - med) for v in values], 0.5) or 1e-9
    zs = [(v - med) / (1.4826 * mad) for v in values]
    return [clamp(z, -cap, cap) for z in zs]


def _kmeans_1d_thresholds(values: List[float], k: int = 4, max_iter: int = 100) -> Tuple[float, float, float]:
    """Simple 1D k-means to derive 3 thresholds between 4 cluster centers."""
    xs = sorted(values)
    n = len(xs)
    if n < k or len(set(xs)) <= 1:
        return (_percentile(xs, 0.50), _percentile(xs, 0.80), _percentile(xs, 0.95))
    centers = [xs[int((i+1)*n/(k+1))] for i in range(k)]
    for _ in range(max_iter):
        clusters = [[] for _ in range(k)]
        for v in xs:
            j = min(range(k), key=lambda j: abs(v - centers[j]))
            clusters[j].append(v)
        new_centers = [ (sum(c)/len(c) if c else centers[i]) for i, c in enumerate(clusters) ]
        if all(abs(a-b) < 1e-9 for a,b in zip(new_centers, centers)):
            centers = new_centers
            break
        centers = new_centers
    centers.sort()
    t1 = 0.5 * (centers[0] + centers[1])
    t2 = 0.5 * (centers[1] + centers[2])
    t3 = 0.5 * (centers[2] + centers[3])
    return (t1, t2, t3)


def _degenerate(scores: List[float]) -> bool:
    if not scores:
        return True
    lo, hi = min(scores), max(scores)
    return abs(hi - lo) < 1e-9


def _safe_weights(keys: List[str], weights: Optional[Dict[str, float]]) -> Dict[str, float]:
    if not weights:
        return {k: 1.0 for k in keys}
    w = {k: float(weights.get(k, 1.0)) for k in keys}
    # limita pesos a [-2, 2]
    for k in w:
        w[k] = clamp(w[k], -2.0, 2.0)
    return w


def _extract_fields_cfg(params: Optional[Dict[str, Any]]) -> Tuple[List[str], Dict[str, float]]:
    """From params={ 'type':..., 'companyCriticality':..., 'fields': {name:{'weight':w}} },
    return (field_names, weights_dict in [-2,2]). If params or fields missing, returns ([],{}).
    """
    if not params or not isinstance(params, dict):
        return [], {}
    fields = params.get('fields') or {}
    if not isinstance(fields, dict):
        return [], {}
    names: List[str] = []
    weights: Dict[str, float] = {}
    for fname, cfg in fields.items():
        if not isinstance(fname, str):
            continue
        w = 1.0
        if isinstance(cfg, dict) and 'weight' in cfg:
            try:
                w = float(cfg['weight'])
            except Exception:
                w = 1.0
        w = clamp(w, -2.0, 2.0)
        names.append(fname)
        weights[fname] = w
    return names, weights


def compute_raw_scores(
    items: List[Dict[str, Any]],
    *,
    weights: Optional[Dict[str, float]] = None,
    ref_year: Optional[int] = None,
    ref_month: Optional[int] = None,
    horizon_months: int = 60,
    date_mode: str = "exp",
    date_k: float = 3.0,
) -> List[Dict[str, Any]]:
    """
    Calcula um score CRU (não reescalado) por item:
      - Normaliza features em 0..10 (cve, epss, criticidade, date)
      - Converte cada coluna para robust-z (mediana+MAD, cap [-3,3])
      - Soma ponderada (pesos em [-2,2]) => _raw_score (sem 0..100)
    Retorna a lista de itens com _features e _raw_score.
    """
    if not items:
        return []

    # 1) extrai features normalizadas
    feats_list = [to_features_0_10(it, ref_year=ref_year, ref_month=ref_month) for it in items]
    # corrige score de data com os parâmetros escolhidos
    for i, it in enumerate(items):
        feats_list[i]["date"] = date_score_months(
            it.get("date"),
            ref_year=ref_year,
            ref_month=ref_month,
            horizon_months=horizon_months,
            mode=date_mode,
            k=date_k,
        )

    # 2) robust-z por coluna (cap em [-3,3])
    cols = {k: [f[k] for f in feats_list] for k in ("cve", "epss", "criticidade", "date")}
    rz = {k: _robust_z_list(cols[k], cap=3.0) for k in cols}

    # 3) combina com pesos (sem reescalar)
    keys = ["cve", "epss", "criticidade", "date"]
    w = _safe_weights(keys, weights)

    out = []
    for i, it in enumerate(items):
        s = 0.0
        for k in keys:
            s += rz[k][i] * w[k]
        o = dict(it)
        o["_features"] = feats_list[i]
        o["_raw_score"] = round(s, 6)
        out.append(o)

    # ordena desc por score cru
    out.sort(key=lambda r: r["_raw_score"], reverse=True)
    return out


def compute_raw_scores_dynamic(
    items: List[Dict[str, Any]],
    *,
    params: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Computes _raw_score using exactly the fields provided in params['fields'] with their 'weight'.
    Field values are expected to already be normalized to 0..10 in each item dict.
    Robustness: per-field robust-z (median+MAD, cap to [-3,3]); weighted sum with weights in [-2,2].
    """
    if not items:
        return []
    field_names, weights = _extract_fields_cfg(params)
    if not field_names:
        return []

    # collect per-field values
    cols: Dict[str, List[float]] = {f: [] for f in field_names}
    for it in items:
        for f in field_names:
            v = it.get(f, 0)
            try:
                x = float(v if v is not None else 0)
            except Exception:
                x = 0.0
            # clamp to 0..10 as contract
            x = clamp(x, 0.0, 10.0)
            cols[f].append(x)

    # per-field robust z-scores
    rz_cols: Dict[str, List[float]] = {f: _robust_z_list(cols[f], cap=3.0) for f in field_names}

    # combine with weights
    out: List[Dict[str, Any]] = []
    for i, it in enumerate(items):
        s = 0.0
        for f in field_names:
            s += rz_cols[f][i] * weights[f]
        o = dict(it)
        o['_raw_score'] = round(s, 6)
        o['_fields_used'] = field_names
        o['_weights_used'] = {f: weights[f] for f in field_names}
        out.append(o)

    out.sort(key=lambda r: r['_raw_score'], reverse=True)
    return out


def compute_scores_and_clusters_free(
    items: List[Dict[str, Any]],
    *,
    weights: Optional[Dict[str, float]] = None,
    ref_year: Optional[int] = None,
    ref_month: Optional[int] = None,
    horizon_months: int = 60,
    date_mode: str = "exp",
    date_k: float = 3.0,
    cut_mode: str = "kmeans",  # "kmeans" | "quantiles"
    quantile_cuts: Tuple[float, float, float] = (0.50, 0.80, 0.95),
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Clusterização sobre o score CRU (não reescalado). Thresholds e classes
    são definidos diretamente sobre a distribuição de _raw_score.
    """
    # If params with fields provided, use dynamic-fields pipeline; else fallback to default (cve/epss/criticidade/date)
    field_names, _ws = _extract_fields_cfg(params)
    if field_names:
        base = compute_raw_scores_dynamic(items, params=params)
    else:
        base = compute_raw_scores(
            items,
            weights=weights,
            ref_year=ref_year,
            ref_month=ref_month,
            horizon_months=horizon_months,
            date_mode=date_mode,
            date_k=date_k,
        )
    if not base:
        return {"thresholds_raw": {"t1": 0.0, "t2": 0.0, "t3": 0.0}, "items": []}

    scores = [r["_raw_score"] for r in base]

    if _degenerate(scores):
        t1 = t2 = t3 = scores[0]
        for r in base:
            r["_class"] = "media"
        return {"thresholds_raw": {"t1": t1, "t2": t2, "t3": t3}, "items": base}

    if cut_mode == "kmeans":
        t1, t2, t3 = _kmeans_1d_thresholds(scores, k=4)
    else:
        q1, q2, q3 = quantile_cuts
        t1 = _percentile(scores, q1)
        t2 = _percentile(scores, q2)
        t3 = _percentile(scores, q3)

    # classifica por thresholds em _raw_score
    for r in base:
        s = r["_raw_score"]
        if s <= t1:
            r["_class"] = "baixa"
        elif s <= t2:
            r["_class"] = "media"
        elif s <= t3:
            r["_class"] = "alta"
        else:
            r["_class"] = "gravissima"

    return {
        "thresholds_raw": {"t1": round(t1, 6), "t2": round(t2, 6), "t3": round(t3, 6)},
        "items": base,
    }


def triage_select_raw(
    items: List[Dict[str, Any]],
    *,
    capacity: int,
    weights: Optional[Dict[str, float]] = None,
    ref_year: Optional[int] = None,
    ref_month: Optional[int] = None,
    horizon_months: int = 60,
    date_mode: str = "exp",
    date_k: float = 3.0,
    cut_mode: str = "kmeans",
    quantile_cuts: Tuple[float, float, float] = (0.50, 0.80, 0.95),
    suppress_ok: bool = True,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Triagem baseada no score CRU (não reescalado). Define o limiar por capacidade
    diretamente nos _raw_scores e combina com o corte superior (t3) conforme o modo.
    """
    if capacity <= 0 or not items:
        return {"selected": [], "thresholds_raw": {"t1": 0.0, "t2": 0.0, "t3": 0.0}, "threshold_used": 0.0, "population": 0}

    # filtro opcional de itens com 'OK'
    def _has_ok_tag_local(it: Dict[str, Any]) -> bool:
        for key in ("tags", "environments"):
            arr = it.get(key) or []
            if isinstance(arr, list):
                for t in arr:
                    v = None
                    if isinstance(t, dict):
                        v = t.get("value") or t.get("status") or t.get("name")
                    elif isinstance(t, str):
                        v = t
                    if isinstance(v, str) and "ok" in v.lower():
                        return True
        return False

    pool = [it for it in items if not (_has_ok_tag_local(it) if suppress_ok else False)]
    if not pool:
        pool = items[:]

    res = compute_scores_and_clusters_free(
        pool,
        weights=weights,
        ref_year=ref_year,
        ref_month=ref_month,
        horizon_months=horizon_months,
        date_mode=date_mode,
        date_k=date_k,
        cut_mode=cut_mode,
        quantile_cuts=quantile_cuts,
        params=params,
    )

    scored = res["items"]
    scores = [r["_raw_score"] for r in scored]
    n = len(scores)

    # limiar por capacidade diretamente no score cru
    frac = max(0.0, min(1.0, 1.0 - (capacity / max(1, n))))
    T_cap = _percentile(scores, frac)

    t3 = res["thresholds_raw"]["t3"]
    T = max(T_cap, t3)  # prioriza topo/gravíssima

    selected = [r for r in scored if r["_raw_score"] >= T]
    selected.sort(key=lambda r: r["_raw_score"], reverse=True)

    if len(selected) > capacity:
        selected = selected[:capacity]
    elif len(selected) < capacity:
        leftover = [r for r in scored if r not in selected]
        leftover.sort(key=lambda r: r["_raw_score"], reverse=True)
        need = capacity - len(selected)
        selected += leftover[:need]

    return {
        "selected": selected,
        "thresholds_raw": res["thresholds_raw"],
        "threshold_used": round(T, 6),
        "population": n,
    }


def final_value_free(
    item: Dict[str, Any],
    population: List[Dict[str, Any]],
    *,
    params: Optional[Dict[str, Any]] = None,
    **kwargs,
) -> Tuple[float, str]:
    """
    Retorna (_raw_score, classe) do item usando thresholds aprendidos na população,
    SEM reescalar para 0..100.
    """
    pool = population + [item] if item not in population else population
    res = compute_scores_and_clusters_free(pool, params=params, **kwargs)
    # procurar o item na lista classificada
    target = None
    for r in res["items"]:
        if all(r.get(k) == item.get(k) for k in ("name", "date", "cve_id")):
            target = r
            break
    if target is None:
        target = res["items"][0]
    return target["_raw_score"], target["_class"]


# ==== Additional helpers and selection (gravissima) ====
from typing import Any


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


def _normalize_item_minimal(it: Dict[str, Any]) -> Dict[str, Any]:
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


def _weights_to_params(weights: Dict[str, float]) -> Dict[str, Any]:
    fields = {}
    for k, w in (weights or {}).items():
        try:
            fields[k] = {"weight": float(w)}
        except Exception:
            fields[k] = {"weight": 1.0}
    return {"fields": fields}


def select_top_gravissima(
    *,
    collection,
    weights: Dict[str, float],
    limit: int = 30,
    query: Optional[Dict[str, Any]] = None,
    projection: Optional[Dict[str, int]] = None,
    cut_mode: str = "quantiles",
    quantile_cuts: Tuple[float, float, float] = (0.60, 0.85, 0.97),
) -> Dict[str, Any]:
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
    cursor = collection.find(q, proj)
    items = [ _normalize_item_minimal(doc) for doc in cursor ]
    if not items:
        return {"thresholds_raw": {"t1": 0.0, "t2": 0.0, "t3": 0.0}, "items": [], "selected": []}
    params = _weights_to_params(weights)
    res = compute_scores_and_clusters_free(
        items,
        params=params,
        cut_mode=cut_mode,
        quantile_cuts=quantile_cuts,
    )
    grav = [r for r in res["items"] if r.get("_class") == "gravissima"]
    grav.sort(key=lambda r: r.get("_raw_score", 0.0), reverse=True)
    sel = grav[:max(0, int(limit))]
    return {"thresholds_raw": res.get("thresholds_raw"), "items": res["items"], "selected": sel}