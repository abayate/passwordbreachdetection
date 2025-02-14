import hashlib

pass_filename = "List of Ashley Madison Passwords"

password = input ("Enter your password: ").strip() # Allows user input and removes spaces from it.

enc_password = password.encode("utf-8")
password_hash = hashlib.md5(enc_password.strip()).hexdigest()
print(f"Hash of input password ({password}): {password_hash}")

password_hashes = set()

with open (pass_filename, "r", encoding= "utf-8") as pass_file:
    for word in pass_file:
        word=word.strip()
        enc_word = word.encode('utf-8')
        enc_hash = hashlib.md5(enc_word).hexdigest()
        password_hashes.add(enc_hash)

    if password_hash in password_hashes:
        print("This password was found in this breach. The password you entered was" + " " + password + ".")
    else:
        print("This password was NOT found in this breach.")

