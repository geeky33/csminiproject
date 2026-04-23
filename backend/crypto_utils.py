from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

# ---------------- LOAD KEYS ---------------- #
def load_public_key(path):
    return RSA.import_key(open(path, "rb").read())

def load_private_key(path, password):
    return RSA.import_key(open(path, "rb").read(), passphrase=password)

# ---------------- SIGNATURE ---------------- #
def sign_data(data, private_key):
    h = SHA256.new(data)
    return pkcs1_15.new(private_key).sign(h)

def verify_signature(data, signature, public_key):
    h = SHA256.new(data)
    pkcs1_15.new(public_key).verify(h, signature)

# ---------------- ENCRYPT ---------------- #
def encrypt_file(input_file, output_file, public_key_path, private_key_path, password):
    public_key = load_public_key(public_key_path)
    private_key = load_private_key(private_key_path, password)

    with open(input_file, "rb") as f:
        data = f.read()

    aes_key = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)

    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    file_hash = SHA256.new(data).digest()
    signature = sign_data(data, private_key)

    enc_aes_key = PKCS1_OAEP.new(public_key).encrypt(aes_key)

    with open(output_file, "wb") as f:
        f.write(enc_aes_key)
        f.write(cipher_aes.nonce)
        f.write(tag)
        f.write(file_hash)
        f.write(len(signature).to_bytes(2, "big"))
        f.write(signature)
        f.write(ciphertext)

# ---------------- DECRYPT ---------------- #
def decrypt_file(input_file, output_file, private_key_path, public_key_path, password):
    private_key = load_private_key(private_key_path, password)
    public_key = load_public_key(public_key_path)

    with open(input_file, "rb") as f:
        enc_aes_key = f.read(256)
        nonce = f.read(16)
        tag = f.read(16)
        file_hash = f.read(32)

        sig_len = int.from_bytes(f.read(2), "big")
        signature = f.read(sig_len)

        ciphertext = f.read()

    aes_key = PKCS1_OAEP.new(private_key).decrypt(enc_aes_key)

    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # integrity check
    if SHA256.new(data).digest() != file_hash:
        raise ValueError("Integrity check failed")

    # signature verification
    verify_signature(data, signature, public_key)

    with open(output_file, "wb") as f:
        f.write(data)

# ---------------- FINGERPRINT ---------------- #
def get_key_fingerprint(public_key_path):
    key = open(public_key_path, "rb").read()
    h = SHA256.new(key).hexdigest()
    return ":".join([h[i:i+2] for i in range(0, 32, 2)])