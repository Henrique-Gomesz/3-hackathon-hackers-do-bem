


from typing import List, Dict, Any, Optional, Tuple


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
    ensure_top_frac: float = 0.10,
    ensure_min_n: int = 5,
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

    # 4) Garante pelo menos top-X como gravíssima (dinamicamente)
    n = len(base)
    min_crit = max(int(math.ceil(n * clamp(ensure_top_frac, 0.0, 1.0))), ensure_min_n)
    base.sort(key=lambda r: r['_score_0_100'], reverse=True)
    for i, row in enumerate(base):
        row['_is_critical'] = (row['_class'] == 'gravissima') or (i < min_crit)

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