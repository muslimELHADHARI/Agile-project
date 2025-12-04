import os
import json
import requests
from datetime import datetime
from dotenv import load_dotenv
from typing import Dict, Any

load_dotenv()

# Configuration
RESULTS_DIR = "results"
XAI_API_KEY = os.getenv("XAI_API_KEY")
XAI_API_URL = "https://api.x.ai/v1/chat/completions"  # API Grok (équivalent OpenAI)

def load_json_file(filepath: str) -> Dict[str, Any]:
    """Charge un fichier JSON, gère les erreurs."""
    if not os.path.exists(filepath):
        print(f"⚠️  Fichier manquant : {filepath} (ignoré)")
        return {}
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def fuse_results() -> Dict[str, Any]:
    """Fusionne tous les résultats en un JSON unifié."""
    merged = {
        "target": "unknown",  # À récupérer du premier fichier ou passer en param
        "timestamp": datetime.now().isoformat(),
        "reconnaissance": {},
        "vulnerabilities": {
            "sql_injection": [],
            "directory_enumeration": [],
            "other": []
        },
        "tools_used": []
    }

    # Charge Nmap (reconnaissance)
    nmap_data = load_json_file(os.path.join(RESULTS_DIR, "nmap_results.json"))
    if nmap_data:
        merged["target"] = nmap_data.get("target", merged["target"])
        merged["reconnaissance"]["nmap"] = nmap_data
        merged["tools_used"].append("nmap")

    # Charge SQLmap (vulnérabilités)
    sqlmap_data = load_json_file(os.path.join(RESULTS_DIR, "sqlmap_results.json"))
    if sqlmap_data:
        merged["vulnerabilities"]["sql_injection"] = sqlmap_data.get("vulnerabilities", [])
        merged["tools_used"].append("sqlmap")

    # Charge Gobuster (vulnérabilités)
    gobuster_data = load_json_file(os.path.join(RESULTS_DIR, "gobuster_results.json"))
    if gobuster_data:
        merged["vulnerabilities"]["directory_enumeration"] = gobuster_data.get("discovered_directories", [])
        merged["tools_used"].append("gobuster")

    # Ajoute une estimation de sévérité globale si pas présente
    for vuln_list in merged["vulnerabilities"].values():
        for vuln in vuln_list:
            if "severity" not in vuln:
                vuln["severity"] = "medium"  # Par défaut, à affiner par outil

    return merged

def analyze_with_grok(merged_json: Dict[str, Any]) -> str:
    """Envoie à Grok pour synthèse."""
    prompt = f"""
    Tu es un expert en cybersécurité. Analyse ces résultats de scans automatisés sur une cible autorisée ({merged_json['target']}).

    Données : {json.dumps(merged_json, indent=2, ensure_ascii=False)}

    Génère une synthèse structurée en français :
    1. **Résumé exécutif** : Vue d'ensemble (ports ouverts, technologies, vulnérabilités critiques).
    2. **Tableau des vulnérabilités** : Format Markdown | Vulnérabilité | URL/Port | Sévérité (Haute/Moyenne/Faible) | Détails |
    3. **Recommandations** : Actions prioritaires pour corriger (classées par sévérité).

    Sois précis, concis et actionnable.
    """

    headers = {
        "Authorization": f"Bearer {XAI_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "messages": [{"role": "user", "content": prompt}],
        "model": "grok-beta",  # Modèle Grok actuel
        "temperature": 0.1,    # Pour plus de précision
        "max_tokens": 2000
    }

    response = requests.post(XAI_API_URL, headers=headers, json=data)
    if response.status_code == 200:
        return response.json()["choices"][0]["message"]["content"]
    else:
        raise Exception(f"Erreur API Grok : {response.text}")

def main():
    # 1. Fusion
    merged = fuse_results()
    output_dir = "outputs"
    os.makedirs(output_dir, exist_ok=True)

    # Sauvegarde JSON fusionné
    merged_path = os.path.join(output_dir, "merged_results.json")
    with open(merged_path, 'w', encoding='utf-8') as f:
        json.dump(merged, f, indent=2, ensure_ascii=False)
    print(f"JSON fusionné : {merged_path}")

    # 2. Analyse LLM
    try:
        analysis = analyze_with_grok(merged)
        analysis_path = os.path.join(output_dir, "llm_analysis.txt")
        json_analysis_path = os.path.join(output_dir, "llm_analysis.json")
        
        with open(analysis_path, 'w', encoding='utf-8') as f:
            f.write(analysis)
        with open(json_analysis_path, 'w', encoding='utf-8') as f:
            json.dump({"analysis": analysis, "merged_data": merged}, f, indent=2, ensure_ascii=False)
        
        print(f"Analyse Grok : {analysis_path}")
        print("\n--- Aperçu de l'analyse ---\n", analysis[:500], "...")
    except Exception as e:
        print(f"Erreur analyse : {e}")

if __name__ == "__main__":
    main()