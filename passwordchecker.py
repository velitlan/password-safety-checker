import requests
import hashlib
import re
import secrets
import string
import msvcrt

def generate_strong_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

def frage_nach_vorschlag():
    print("\nMöchtest du ein sicheres Passwort automatisch generieren lassen? (y/n)")
    taste = msvcrt.getch().decode('utf-8').lower()
    if taste == 'y':
        neues_passwort = generate_strong_password()
        print("\nHier dein sicherer Passwortvorschlag:")
        print(neues_passwort)
    else:
        print("\nOkay.")

def hash_password(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    return sha1[:5], sha1[5:]

def check_pwned_api(prefix):
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        raise RuntimeError(f"API-Anfrage fehlgeschlagen: {e}")

def is_password_pwned(password):
    prefix, suffix = hash_password(password)
    hashes = check_pwned_api(prefix)

    for line in hashes.splitlines():
        parts = line.split(':')
        if len(parts) == 2 and parts[0] == suffix:
            return int(parts[1])
    return 0

def bewertung_passwort(passwort):
    punkte = 0
    feedback = []

    if len(passwort) >= 12:
        punkte += 2
        feedback.append("Gute Länge (12+ Zeichen)")
    elif len(passwort) >= 8:
        punkte += 1
        feedback.append("Okay, aber besser wären 12+ Zeichen")
    else:
        feedback.append("Zu kurz (unter 8 Zeichen)")

    if re.search(r'[a-z]', passwort): punkte += 1
    else: feedback.append("Keine Kleinbuchstaben")

    if re.search(r'[A-Z]', passwort): punkte += 1
    else: feedback.append("Keine Großbuchstaben")

    if re.search(r'[0-9]', passwort): punkte += 1
    else: feedback.append("Keine Zahlen")

    if re.search(r'[\W_]', passwort): punkte += 1
    else: feedback.append("Keine Sonderzeichen")

    stufe = (
        "Starkes Passwort" if punkte >= 6 else
        "Mittelstarkes Passwort" if punkte >= 4 else
        "Schwaches Passwort"
    )
    return stufe, feedback

def main():
    password = input("Gib dein Passwort ein:\n")

    stufe, infos = bewertung_passwort(password)
    print("\nPasswortbewertung:", stufe)
    for zeile in infos:
        print("-", zeile)

    print("\nLeak-Check:")
    try:
        count = is_password_pwned(password)
        if count:
            print(f"Dein Passwort wurde {count} Mal in Datenleaks gefunden. Ändere es dringend.")
            frage_nach_vorschlag()
        else:
            print("Dein Passwort wurde bisher nicht geleakt.")
    except RuntimeError as e:
        print("Fehler bei der Prüfung:", e)

if __name__ == "__main__":
    main()