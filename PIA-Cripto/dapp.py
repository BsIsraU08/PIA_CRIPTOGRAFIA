import getpass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature, decode_dss_signature
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

def generar_llaves(usuario):
    # Generación de una nueva llave privada utilizando curvas elípticas
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())

    # Obtención de la llave pública a partir de la llave privada
    public_key = private_key.public_key()

    # Serialización de las llaves en formato PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Guardar las llaves en archivos
    with open(f'{usuario}_private_key.pem', 'wb') as f:
        f.write(private_pem)

    with open(f'{usuario}_public_key.pem', 'wb') as f:
        f.write(public_pem)


def encrypt_private_key(private_key, password):
    salt = b'salt'  # Sal utilizada para el cifrado
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    ciphertext = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(key)
    )
    return ciphertext


def decrypt_private_key(encrypted_private_key, password):
    try:
        private_key = serialization.load_pem_private_key(
            encrypted_private_key,
            password=password,
            backend=default_backend()
        )
        return private_key
    except:
        return None


def sign_message(private_key, message):
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    r, s = decode_dss_signature(signature)

    # Guardar el mensaje firmado en un archivo
    with open("mensaje_firmado.txt", "w") as f:
        f.write(f"Mensaje: {message}\n")
        f.write(f"Firma:\n")
        f.write(f"r: {r}\n")
        f.write(f"s: {s}\n")


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        usuario = request.form['usuario']
        contrasena = request.form['contrasena']

        generar_llaves(usuario)

        # Cifrar y guardar la clave privada
        private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        encrypted_private_key = encrypt_private_key(private_key, contrasena.encode())

        with open(f'{usuario}_private_key.pem', 'wb') as f:
            f.write(encrypted_private_key)

        return redirect('/login')

    return render_template('registro.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        contrasena = request.form['contrasena']

        # Leer la clave privada cifrada del archivo
        with open(f'{usuario}_private_key.pem', 'rb') as f:
            encrypted_private_key = f.read()

        # Derivar la clave de cifrado utilizando la contraseña
        salt = b'salt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(contrasena.encode())

        # Intentar descifrar la clave privada
        private_key = decrypt_private_key(encrypted_private_key, key)

        if private_key:
            return redirect('/ingresar_mensaje')
        else:
            return redirect('/login')

    return render_template('login.html')


@app.route('/ingresar_mensaje', methods=['GET', 'POST'])
def ingresar_mensaje():
    if request.method == 'POST':
        usuario = request.form['usuario']
        contrasena = request.form['contrasena']

        # Leer la clave privada cifrada del archivo
        with open(f'{usuario}_private_key.pem', 'rb') as f:
            encrypted_private_key = f.read()

        # Derivar la clave de cifrado utilizando la contraseña
        salt = b'salt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(contrasena.encode())

        # Intentar descifrar la clave privada
        private_key = decrypt_private_key(encrypted_private_key, key)

        if private_key:
            message = request.form['mensaje']
            sign_message(private_key, message.encode())
            return "Mensaje firmado y guardado en 'mensaje_firmado.txt'"
        else:
            return redirect('/login')

    return render_template('ingresar_mensaje.html')

if __name__ == "__main__":
    app.run(debug=True)
