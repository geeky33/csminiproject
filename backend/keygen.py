import os, getpass
from Crypto.PublicKey import RSA

KEY_DIR = "keys"
os.makedirs(KEY_DIR, exist_ok=True)

priv_path = os.path.join(KEY_DIR, "private.pem")
pub_path = os.path.join(KEY_DIR, "public.pem")

if os.path.exists(priv_path):
    choice = input("Keys exist. Overwrite? (y/n): ")
    if choice.lower() != "y":
        print("Cancelled.")
        exit()

password = getpass.getpass("Enter password for private key: ")

key = RSA.generate(2048)

private_key = key.export_key(
    passphrase=password,
    pkcs=8,
    protection="scryptAndAES128-CBC"
)

public_key = key.publickey().export_key()

open(priv_path, "wb").write(private_key)
open(pub_path, "wb").write(public_key)

print("Keys generated successfully")