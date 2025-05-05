import requests
import hashlib
import re
import secrets
import string
import msvcrt

#Passwortvorschlag
def frage_nach_vorschlag():
    print("\nMöchtest du ein sicheres Passwort automatisch generieren lassen? (y/n)")

    taste = msvcrt.getch().decode('utf-8').lower()
    if taste == 'y':
        def generate_strong_password(length=16):
             characters = string.ascii_letters + string.digits + string.punctuation
             return ''.join(secrets.choice(characters) for _ in range(length))
        neues_passwort = generate_strong_password()
        print("\nHier dein sicherer Passwortvorschlag:")
        print(neues_passwort)
    else:
        print("\nOkay.")

#Umwandlung des Passworts in SHA1-Hash
def hash_password(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    return sha1[:5], sha1[5:]

#Abfrage bei der PwnedPasswords API
def check_pwned_api(prefix):
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f"API-Fehler: {response.status_code}")
    return response.text

#Prüfung des Passworts auf Datenleaks
def is_password_pwned(password):
    prefix, suffix = hash_password(password)
    hashes = check_pwned_api(prefix)

    for line in hashes.splitlines():
        hash_suffix, count = line.split(':')
        if hash_suffix == suffix:
            return int(count)
    return 0

#Bewertung der Passwortstärke
def bewertung_passwort(passwort):
    punkte = 0
    feedback = []

    #Länge
    if len(passwort) >= 12:
        punkte += 2
        feedback.append("Gute Länge (12+ Zeichen)")
    elif len(passwort) >= 8:
        punkte += 1
        feedback.append("Okay, aber besser wären 12+ Zeichen")
    else:
        feedback.append("Zu kurz (unter 8 Zeichen)")

    #Klein- und Großbuchstaben
    if re.search(r'[a-z]', passwort):
        punkte += 1
    else:
        feedback.append("Keine Kleinbuchstaben")
    
    if re.search(r'[A-Z]', passwort):
        punkte += 1
    else:
        feedback.append("Keine Großbuchstaben")
    
    #Zahlen
    if re.search(r'[0-9]', passwort):
        punkte += 1
    else:
        feedback.append("Keine Zahlen")
    
    #Sonderzeichen
    if re.search(r'[\W_]', passwort):
        punkte += 1
    else:
        feedback.append("Keine Sonderzeichen")

    #Bewertung
    if punkte >= 6:
        stufe = "Starkes Passwort"
    elif punkte >= 4:
        stufe = "Mittelstarkes Passwort"
    else:
        stufe = "Schwaches Passwort"

    return stufe, feedback

#Hauptfunktion
def main():
    password = input("Gib dein Passwort ein:\n")

    #Stärke bewerten
    stufe, infos = bewertung_passwort(password)
    print("\nPasswortbewertung:")
    print(stufe)
    for zeile in infos:
        print("-", zeile)

    #Prüfung auf Datenleaks
    count = is_password_pwned(password)
    print("\nLeak-Check:")
    if count:
        print(f"Dein Passwort wurde {count} Mal in Datenleaks gefunden. Ändere es dringend.")
        frage_nach_vorschlag()
    else:
              print("Dein Passwort wurde bisher nicht geleakt.")

#Programmstart
if __name__ == "__main__":
    main()