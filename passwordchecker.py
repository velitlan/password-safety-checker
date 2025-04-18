import requests
import hashlib

# Passwort wird in SHA1 umgewandelt
def hash_password(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    return sha1[:5], sha1[5:]

# Abfrage bei der HIBP-API
def check_pwned_api(prefix):
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f"API-Fehler: {response.status_code}")
    return response.text

# Prüfen, ob Passwort geleakt wurde
def is_password_pwned(password):
    prefix, suffix = hash_password(password)
    hashes = check_pwned_api(prefix)

    for line in hashes.splitlines():
        hash_suffix, count = line.split(':')
        if hash_suffix == suffix:
            return int(count)
    return 0

# Hauptfunktion
def main():
    password = input("Gib dein Passwort ein:\n")
    count = is_password_pwned(password)

    if count:
        print(f"Dein Passwort wurde {count} mal in Datenleaks gefunden. Ändere es unbedingt!")
    else:
        print("Dein Passwort wurde bisher nicht geleakt.")

if __name__ == "__main__":
    main()
