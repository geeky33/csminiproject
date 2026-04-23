import streamlit as st
import os, zipfile, shutil
from backend.crypto_utils import *

st.set_page_config(page_title="Secure File Transfer")

# ---------------- CLEAN TEMP ---------------- #
shutil.rmtree("temp", ignore_errors=True)
os.makedirs("temp", exist_ok=True)

st.title("Secure File Transfer")
st.caption("AES + RSA with Integrity and Digital Signature")

# ---------------- INPUT ---------------- #
files = st.file_uploader("Upload file(s)", accept_multiple_files=True)
password = st.text_input("Private key password", type="password")

# ---------------- PASSWORD STRENGTH ---------------- #
def password_strength(p):
    if len(p) < 4: return "Weak"
    elif len(p) < 8: return "Medium"
    return "Strong"

if password:
    st.write("Password strength:", password_strength(password))

# ---------------- KEY INFO ---------------- #
with st.expander("Key Information"):
    st.code(get_key_fingerprint("keys/public.pem"))

# ---------------- METADATA ---------------- #
if files:
    st.subheader("File Details")
    for f in files:
        data = f.read()
        st.info(f"{f.name} | {round(len(data)/1024,2)} KB")
        f.seek(0)

# ---------------- ENCRYPT ---------------- #
if st.button("Encrypt Files"):

    if not files:
        st.error("Upload files first")
    elif not password:
        st.error("Enter password")
    else:
        zip_path = "temp/encrypted.zip"
        zf = zipfile.ZipFile(zip_path, "w")

        for f in files:
            data = f.read()
            f.seek(0)

            path = f"temp/{f.name}"
            open(path, "wb").write(data)

            enc_path = path + ".enc"

            encrypt_file(
                path,
                enc_path,
                "keys/public.pem",
                "keys/private.pem",
                password
            )

            zf.write(enc_path, arcname=os.path.basename(enc_path))

        zf.close()

        st.success("Encryption complete")

        with open(zip_path, "rb") as f:
            st.download_button("Download ZIP", f)

# ---------------- DECRYPT ---------------- #
st.subheader("Decrypt")

enc_file = st.file_uploader("Upload .enc file", type=["enc"])

if enc_file:
    st.session_state["enc_loaded"] = True

if st.button("Decrypt"):

    if not enc_file:
        st.error("Upload .enc file")
    elif not password:
        st.error("Enter password")
    else:
        enc_path = "temp/current.enc"

        data = enc_file.read()
        enc_file.seek(0)
        open(enc_path, "wb").write(data)

        try:
            decrypt_file(
                enc_path,
                "temp/output",
                "keys/private.pem",
                "keys/public.pem",
                password
            )

            with open("temp/output", "rb") as f:
                st.download_button("Download Decrypted File", f)

            st.success("Decryption successful")

        except Exception as e:
            st.error(str(e))

