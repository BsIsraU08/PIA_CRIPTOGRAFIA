import getpass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

def GenerarLlaves(usuario):
    try:
        private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(f'{usuario}_private_key.pem', 'wb') as f:
            f.write(private_pem)
            
        with open(f'{usuario}_public_key.pem', 'wb') as f:
            f.write(public_pem)
        
        print("Llaves generadas exitosamente.")
    except Exception as e:
        print("Error al generar las llaves:")

def encrypt_private_key(private_key, password):
    try:
        salt = b'salt'
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
    except Exception as e:
        print("Error al cifrar la clave privada:")
        return None

def verificar_credenciales(usuario, contrasena):
    try:
        with open(f'{usuario}_private_key.pem', 'rb') as f:
            encrypted_private_key = f.read()

        salt = b'salt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(contrasena.encode())

        private_key = serialization.load_pem_private_key(
            encrypted_private_key,
            password=key,
            backend=default_backend()
        )
        return private_key
    except Exception as e:
        print("Error al verificar las credenciales:")
        return None

def encrypt_with_fernet(data):
    try:
        key = Fernet.generate_key()
        with open('filekey.key', 'wb') as filekey:
            filekey.write(key)
        
        with open('filekey.key', 'rb') as filekey:
            key = filekey.read()
        
        fernet = Fernet(key)
        encrypted = fernet.encrypt(data.encode())
        print("El mensaje cifrado es:", encrypted)
    except Exception as e:
        print("Error al cifrar el mensaje:")

def decrypt_with_fernet(ciphertext):
    try:
        with open('filekey.key', 'rb') as filekey:
            key = filekey.read()
        
        fernet = Fernet(key)
        plaintext = fernet.decrypt(ciphertext)
        print("El mensaje original es:", plaintext.decode())
    except Exception as e:
        print("Error al descifrar el mensaje:")

def firmar_archivo(private_key, archivo_a_firmar, archivo_firma):
    try:
        with open(archivo_a_firmar, 'rb') as file:
            data = file.read()

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        hash_value = digest.finalize()

        signature = private_key.sign(
            hash_value,
            ec.ECDSA(hashes.SHA256())
        )

        with open(archivo_firma, 'wb') as file:
            file.write(signature)

        print("Archivo firmado exitosamente.")
    except Exception as e:
        print("Error al firmar el archivo:")

def menu():
    while True:
        try:
            seleccion = int(input("Por favor selecciona la opción que deseas realizar:\n1) Iniciar sesión\n2) Registrarte\n3) Salir\n"))

            if seleccion == 1:
                usuario = input("Ingresa tu nombre de usuario: ")
                contrasena = getpass.getpass("Ingresa tu contraseña: ")
                private_key = verificar_credenciales(usuario, contrasena)
                if private_key:
                    print("Inicio de sesión exitoso.")
                    while True:
                        try:
                            seleccion = int(input("Por favor selecciona la opción que deseas realizar:\n1) Cifrar Mensaje\n2) Descifrar mensaje\n3) Firmar archivo\n4) Salir\n"))
                            if seleccion == 1:
                                data = input("Por favor ingresa el mensaje a cifrar: ")
                                encrypt_with_fernet(data)
                            elif seleccion == 2:
                                ciphertext = input("Ingresa el mensaje a descifrar: ")
                                decrypt_with_fernet(ciphertext)
                            elif seleccion == 3:
                                archivo_a_firmar = input("Ingresa el nombre del archivo a firmar (debe estar en la misma ruta que el archivo Python): ")
                                archivo_firma = input("Ingresa el nombre del archivo de firma: ")
                                firmar_archivo(private_key, archivo_a_firmar, archivo_firma)
                            elif seleccion == 4:
                                break
                            else:
                                print("Opción inválida. Por favor, selecciona una opción válida.")
                        except ValueError:
                            print("Debes ingresar un número como opción.")
                else:
                    print("Credenciales inválidas. Por favor, intenta nuevamente.")
            elif seleccion == 2:
                usuario = input("Ingresa tu nombre de usuario: ")
                contrasena = getpass.getpass("Ingresa tu contraseña: ")
                GenerarLlaves(usuario)
                private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
                encrypted_private_key = encrypt_private_key(private_key, contrasena.encode())

                with open(f'{usuario}_private_key.pem', 'wb') as f:
                    f.write(encrypted_private_key)
            elif seleccion == 3:
                break
            else:
                print("Opción inválida. Por favor, selecciona una opción válida.")
        except ValueError:
            print("Debes ingresar un número como opción.")

if __name__ == "__main__":
    menu()
