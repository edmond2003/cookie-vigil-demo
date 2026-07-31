#!/usr/bin/env python3
"""
normalize_metrics.py
=====================================================================
Normalise les sorties brutes de CookieVigil, Nikto, Nuclei et ZAP,
les compare à la vérité terrain (verite_terrain.yaml) selon les
capacités déclarées de chaque outil (tool_mappings.yaml), et calcule :
  - précision / rappel / F1 / exactitude par outil et par catégorie
  - temps d'exécution moyen ± écart-type par outil (et par route)
  - mémoire pic moyenne ± écart-type par outil (et par route)

Sorties générées dans analyse/resultats/ :
  - detections_brutes.csv      (détail détecté/attendu par route x catégorie x outil)
  - metrics_precision_rappel.csv
  - metrics_performance.csv
  - synthese_latex.tex          (tableau prêt à coller dans le mémoire)

Dépendances : pyyaml, pandas
    pip install pyyaml pandas --break-system-packages

CORRECTIONS 2026-07-22 (v2) :
  - parse_cookievigil() lisait une clé "rule_id" qui n'existe pas dans
    le JSON réel de CookieVigil ; les catégories sont en réalité sous
    la clé "id" à l'intérieur de la liste "issues" de chaque cookie
    (confirmé sur comparaison/cookievigil/run_1/set-bad-cookies.json).
    -> Corrigé : on lit désormais "id" au lieu de "rule_id".
  - ZAP_DURATION_RE ne matchait que "Durée (spider+passif):" alors que
    le script run_zap.sh (version Docker) écrit
    "Durée (access+passif):" -> regex élargi pour accepter les deux.
=====================================================================
"""

import argparse
import json
import re
import statistics
from pathlib import Path

import pandas as pd
import yaml

# ---------------------------------------------------------------------
# 1. Chargement de la configuration
# ---------------------------------------------------------------------

def load_yaml(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def build_ground_truth(gt_config, categories):
    """
    Réapplique les règles CookieVigil (Chapitre 2) sur les attributs
    bruts déclarés dans verite_terrain.yaml pour dériver, pour chaque
    route, l'ensemble des catégories de vulnérabilité attendues
    (agrégation OR sur tous les cookies de la route, car les outils
    généralistes comparés ne raisonnent pas cookie par cookie mais par
    URL/page).
    """
    expires_threshold = gt_config["meta"]["expires_long_threshold_seconds"]
    weak_len = gt_config["meta"]["weak_token_max_length"]

    def is_weak_token(value):
        if value is None or value.startswith("A_CONFIRMER"):
            return None  # inconnu -> exclu du calcul, voir main()
        return len(value) < weak_len and (value.isdigit() or value.isalpha())

    def is_jwt(cookie):
        if cookie.get("is_jwt"):
            return True
        v = cookie.get("value", "") or ""
        parts = v.split(".")
        return len(parts) == 3

    ground_truth = {}
    for route, data in gt_config["routes"].items():
        flags = {c: False for c in categories if c != "JWT_DETECTED"}
        flags["JWT_DETECTED"] = False
        unknown_categories = set()

        for _, cookie in data.get("cookies", {}).items():
            if cookie.get("secure") is False:
                flags["SECURE_MISSING"] = True
            if cookie.get("httponly") is False:
                flags["HTTPONLY_MISSING"] = True

            samesite = cookie.get("samesite")
            if samesite in (None, "", "null", "undefined"):
                flags["SAMESITE_MISSING"] = True
            if samesite == "None" and not cookie.get("secure"):
                flags["SAMESITE_NONE_INSECURE"] = True

            domain = cookie.get("domain")
            if domain and str(domain).startswith("."):
                flags["DOMAIN_TOO_BROAD"] = True

            if cookie.get("path") == "/":
                flags["PATH_TOO_BROAD"] = True

            max_age = cookie.get("max_age_seconds")
            if max_age is not None and max_age > expires_threshold:
                flags["EXPIRES_LONG"] = True

            weak = is_weak_token(cookie.get("value"))
            if weak is None:
                unknown_categories.add("WEAK_TOKEN")
            elif weak:
                flags["WEAK_TOKEN"] = True

            if is_jwt(cookie):
                flags["JWT_DETECTED"] = True

        ground_truth[route] = {"flags": flags, "unknown": unknown_categories}

    return ground_truth


# ---------------------------------------------------------------------
# 2. Parsing des sorties brutes par outil
# ---------------------------------------------------------------------

def parse_cookievigil(run_dir, route):
    """Lit les catégories détectées par CookieVigil.

    Le JSON réel place l'identifiant de catégorie sous la clé "id",
    dans la liste "issues" de chaque cookie (pas "rule_id" comme
    supposé initialement). On cherche récursivement toute clé "id"
    dont la valeur est une chaîne en MAJUSCULES_AVEC_UNDERSCORES pour
    éviter de capter d'autres champs "id" numériques ou non pertinents
    présents ailleurs dans le rapport.
    """
    fpath = run_dir / f"{route}.json"
    if not fpath.exists():
        return set()
    try:
        data = json.loads(fpath.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()

    detected = set()
    id_pattern = re.compile(r"^[A-Z][A-Z0-9_]*$")

    def walk(obj):
        if isinstance(obj, dict):
            val = obj.get("id")
            if isinstance(val, str) and id_pattern.match(val):
                detected.add(val)
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(data)
    return detected


def parse_with_mapping(text_items, mapping):
    """
    text_items : liste de chaînes (messages/alertes brutes de l'outil)
    mapping : liste de dicts {pattern, category} (regex insensibles à la casse)
    """
    detected = set()
    for item in text_items:
        item_low = (item or "").lower()
        for rule in mapping:
            if re.search(rule["pattern"], item_low):
                detected.add(rule["category"])
    return detected


def parse_nikto(run_dir, route, mapping):
    fpath = run_dir / f"{route}.json"
    if not fpath.exists():
        return set()
    try:
        data = json.loads(fpath.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()

    # La structure JSON de Nikto varie selon la version : on couvre les
    # deux formats les plus courants (liste de "vulnerabilities" avec
    # champ "msg", ou top-level "vulnerabilities").
    messages = []
    vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    for v in vulns:
        messages.append(v.get("msg", "") or v.get("message", ""))
    # Filtre : ne garder que les messages mentionnant "cookie"
    messages = [m for m in messages if "cookie" in m.lower()]
    return parse_with_mapping(messages, mapping)


def parse_nuclei(run_dir, route, mapping):
    fpath = run_dir / f"{route}.jsonl"
    if not fpath.exists():
        return set()
    texts = []
    for line in fpath.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        template_id = entry.get("template-id", "") or entry.get("templateID", "")
        name = entry.get("info", {}).get("name", "")
        texts.append(f"{template_id} {name}")
    return parse_with_mapping(texts, mapping)


def parse_zap(run_dir, route, mapping):
    fpath = run_dir / f"{route}_alerts.json"
    if not fpath.exists():
        return set()
    try:
        data = json.loads(fpath.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()
    alerts = data.get("alerts", [])
    texts = [a.get("alert", "") or a.get("name", "") for a in alerts]
    texts = [t for t in texts if "cookie" in t.lower()]
    return parse_with_mapping(texts, mapping)


PARSERS = {
    "cookievigil": lambda run_dir, route, mapping: parse_cookievigil(run_dir, route),
    "nikto": parse_nikto,
    "nuclei": parse_nuclei,
    "zap": parse_zap,
}


# ---------------------------------------------------------------------
# 3. Parsing des logs de performance (/usr/bin/time -v et échantillons ZAP)
# ---------------------------------------------------------------------

TIME_RE = re.compile(r"Elapsed \(wall clock\) time.*?:\s*([0-9:.]+)")
MEM_RE = re.compile(r"Maximum resident set size \(kbytes\):\s*(\d+)")
# Accepte "Durée (spider+passif):" (ancien script) ET
# "Durée (access+passif):" (run_zap.sh version Docker corrigée)
ZAP_DURATION_RE = re.compile(r"Durée \((?:spider|access)\+passif\):\s*(\d+)s")


def parse_elapsed(value):
    """Convertit '0:01.23' ou '1:02:03' en secondes (float)."""
    parts = [float(p) for p in value.split(":")]
    if len(parts) == 2:
        return parts[0] * 60 + parts[1]
    if len(parts) == 3:
        return parts[0] * 3600 + parts[1] * 60 + parts[2]
    return float(parts[0])


def parse_perf_generic(run_dir, route):
    """Pour cookievigil/nikto/nuclei : sortie /usr/bin/time -v classique."""
    fpath = run_dir / f"{route}_time.log"
    if not fpath.exists():
        return None, None
    text = fpath.read_text(encoding="utf-8", errors="ignore")
    t_match = TIME_RE.search(text)
    m_match = MEM_RE.search(text)
    elapsed = parse_elapsed(t_match.group(1)) if t_match else None
    mem_kb = int(m_match.group(1)) if m_match else None
    return elapsed, mem_kb


DOCKER_MEM_RE = re.compile(r"([\d.]+)\s*(KiB|MiB|GiB|B)\b")

_MEM_UNIT_TO_KB = {"B": 1 / 1024, "KiB": 1, "MiB": 1024, "GiB": 1024 * 1024}


def parse_perf_zap(run_dir, route):
    fpath = run_dir / f"{route}_time.log"
    elapsed = None
    if fpath.exists():
        text = fpath.read_text(encoding="utf-8", errors="ignore")
        m = ZAP_DURATION_RE.search(text)
        if m:
            elapsed = float(m.group(1))
    ram_file = run_dir / "ram_samples.log"
    mem_kb = None
    if ram_file.exists():
        samples = []
        for line in ram_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = DOCKER_MEM_RE.search(line)
            if m:
                value, unit = float(m.group(1)), m.group(2)
                samples.append(value * _MEM_UNIT_TO_KB[unit])
        if samples:
            mem_kb = max(samples)
    return elapsed, mem_kb


PERF_PARSERS = {
    "cookievigil": parse_perf_generic,
    "nikto": parse_perf_generic,
    "nuclei": parse_perf_generic,
    "zap": parse_perf_zap,
}


# ---------------------------------------------------------------------
# 4. Orchestration
# ---------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-dir", default=".", help="Racine contenant verite_terrain.yaml, tool_mappings.yaml et comparaison/")
    ap.add_argument("--repeats", type=int, default=5)
    args = ap.parse_args()

    base = Path(args.base_dir)
    gt_config = load_yaml(base / "verite_terrain.yaml")
    tool_config = load_yaml(base / "tool_mappings.yaml")

    categories = tool_config["categories"]
    ground_truth = build_ground_truth(gt_config, categories)
    routes = list(gt_config["routes"].keys())

    out_dir = base / "analyse" / "resultats"
    out_dir.mkdir(parents=True, exist_ok=True)

    detection_rows = []
    perf_rows = []

    for tool, tconf in tool_config["tools"].items():
        capabilities = set(tconf.get("capabilities", []))
        mapping = tconf.get("mapping", [])
        tool_out_dir = base / "comparaison" / tool

        for run_idx in range(1, args.repeats + 1):
            run_dir = tool_out_dir / f"run_{run_idx}"
            if not run_dir.exists():
                continue

            for route in routes:
                # normaliser le nom de route pour les chemins de fichiers
                route_key = route.strip("/")

                detected = PARSERS[tool](run_dir, route_key, mapping)
                expected = ground_truth[route]["flags"]
                unknown = ground_truth[route]["unknown"]

                for cat in categories:
                    if cat not in capabilities:
                        continue  # hors du périmètre de l'outil : non comptabilisé
                    if cat in unknown:
                        continue  # valeur réelle inconnue (A_CONFIRMER) : exclu

                    detection_rows.append({
                        "tool": tool,
                        "run": run_idx,
                        "route": route,
                        "category": cat,
                        "expected": expected[cat],
                        "detected": cat in detected,
                    })

                elapsed, mem_kb = PERF_PARSERS[tool](run_dir, route_key)
                perf_rows.append({
                    "tool": tool, "run": run_idx, "route": route,
                    "elapsed_s": elapsed,
                    "mem_mb": (mem_kb / 1024) if mem_kb else None,
                })

    det_df = pd.DataFrame(detection_rows)
    perf_df = pd.DataFrame(perf_rows)

    det_df.to_csv(out_dir / "detections_brutes.csv", index=False)
    perf_df.to_csv(out_dir / "performance_brute.csv", index=False)

    # ---- Métriques précision / rappel / F1 par outil et catégorie ----
    metric_rows = []
    for (tool, cat), grp in det_df.groupby(["tool", "category"]):
        tp = ((grp.expected == True) & (grp.detected == True)).sum()
        fp = ((grp.expected == False) & (grp.detected == True)).sum()
        fn = ((grp.expected == True) & (grp.detected == False)).sum()
        tn = ((grp.expected == False) & (grp.detected == False)).sum()

        precision = tp / (tp + fp) if (tp + fp) else None
        recall = tp / (tp + fn) if (tp + fn) else None
        f1 = (2 * precision * recall / (precision + recall)
              if precision and recall and (precision + recall) else None)
        accuracy = (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) else None

        metric_rows.append({
            "tool": tool, "category": cat,
            "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "precision": round(precision, 3) if precision is not None else None,
            "recall": round(recall, 3) if recall is not None else None,
            "f1": round(f1, 3) if f1 is not None else None,
            "accuracy": round(accuracy, 3) if accuracy is not None else None,
        })
    metrics_df = pd.DataFrame(metric_rows)
    metrics_df.to_csv(out_dir / "metrics_precision_rappel.csv", index=False)

    # Agrégat global par outil (toutes catégories confondues)
    global_rows = []
    for tool, grp in det_df.groupby("tool"):
        tp = ((grp.expected == True) & (grp.detected == True)).sum()
        fp = ((grp.expected == False) & (grp.detected == True)).sum()
        fn = ((grp.expected == True) & (grp.detected == False)).sum()
        tn = ((grp.expected == False) & (grp.detected == False)).sum()
        precision = tp / (tp + fp) if (tp + fp) else None
        recall = tp / (tp + fn) if (tp + fn) else None
        f1 = (2 * precision * recall / (precision + recall)
              if precision and recall and (precision + recall) else None)
        global_rows.append({
            "tool": tool, "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "precision": round(precision, 3) if precision is not None else None,
            "recall": round(recall, 3) if recall is not None else None,
            "f1": round(f1, 3) if f1 is not None else None,
        })
    global_df = pd.DataFrame(global_rows)

    # ---- Performance moyenne ± écart-type par outil ----
    perf_summary = []
    for tool, grp in perf_df.groupby("tool"):
        times = grp["elapsed_s"].dropna().tolist()
        mems = grp["mem_mb"].dropna().tolist()
        perf_summary.append({
            "tool": tool,
            "temps_moyen_s": round(statistics.mean(times), 2) if times else None,
            "temps_ecart_type_s": round(statistics.pstdev(times), 2) if len(times) > 1 else None,
            "mem_moyenne_mb": round(statistics.mean(mems), 1) if mems else None,
            "mem_ecart_type_mb": round(statistics.pstdev(mems), 1) if len(mems) > 1 else None,
            "n_mesures": len(times),
        })
    perf_summary_df = pd.DataFrame(perf_summary)
    perf_summary_df.to_csv(out_dir / "metrics_performance.csv", index=False)

    # ---- Tableau de synthèse global + export LaTeX ----
    synthese = global_df.merge(perf_summary_df, on="tool", how="outer")
    synthese.to_csv(out_dir / "synthese_globale.csv", index=False)

    latex_lines = [
        r"\begin{table}[htpb]",
        r"\centering",
        r"\caption{Synthèse comparative de CookieVigil face aux outils de référence}",
        r"\label{tab:comparaison-outils}",
        r"\small",
        r"\begin{tabular}{|l|c|c|c|c|c|}",
        r"\hline",
        r"\textbf{Outil} & \textbf{Précision} & \textbf{Rappel} & \textbf{F1} & \textbf{Temps moy. (s)} & \textbf{Mém. moy. (Mo)} \\",
        r"\hline",
    ]
    for _, row in synthese.iterrows():
        latex_lines.append(
            f"{row['tool']} & {row.get('precision', '-')} & {row.get('recall', '-')} & "
            f"{row.get('f1', '-')} & {row.get('temps_moyen_s', '-')} & "
            f"{row.get('mem_moyenne_mb', '-')} \\\\"
        )
    latex_lines += [r"\hline", r"\end{tabular}", r"\end{table}"]
    (out_dir / "synthese_latex.tex").write_text("\n".join(latex_lines), encoding="utf-8")

    print(f"Résultats écrits dans {out_dir}/")
    print(synthese.to_string(index=False))


if __name__ == "__main__":
    main()
