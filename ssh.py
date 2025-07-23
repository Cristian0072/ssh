import shutil
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import os
import base64
import getpass


class SSH:
    # palabras clave para encriptar
    palabras_clave = [
        "Correo electrónico:",
        "Clave:",
        "Celular:",
        "Fecha de nacimiento:",
        "Fecha de vencimiento:",
        "Número de tarjeta:",
        "Teléfono:",
        "Salario:",
        "SSN:",
        "Empleado:",
        "Número de tarjeta:",
        "CVV:",
        "Nombre:",
        "Cédula:",
        "Enero:",
        "Febrero:",
        "Marzo:",
        "Abril:",
        "Mayo:",
        "Junio:",
        "Julio:",
        "Agosto:",
        "Septiembre:",
        "Octubre:",
        "Noviembre:",
        "Diciembre:",
    ]

    # constructor
    def __init__(self, ruta_destino="servidor_destino"):
        # generar claves RSA
        self.clave_privada = RSA.generate(2048)
        self.clave_publica = self.clave_privada.publickey()
        # establecer ruta de destino
        self.ruta_destino = ruta_destino

    def encriptar(self, datos):
        # verificar si hay datos para encriptar
        if not datos:
            raise ValueError("No hay datos para encriptar")
        # cifrar los datos con RSA
        cifrado_rsa = PKCS1_OAEP.new(self.clave_publica, hashAlgo=SHA256)
        clave_aes_encriptada = cifrado_rsa.encrypt(datos.encode())
        return base64.b64encode(clave_aes_encriptada).decode()

    def desencriptar(self, datos):
        # decodificar el paquete JSON
        if not datos:
            raise ValueError("No hay datos para desencriptar")
        # desencriptar la clave AES con RSA
        datos_encriptados = base64.b64decode(datos)
        cifrado_rsa = PKCS1_OAEP.new(self.clave_privada, hashAlgo=SHA256)
        clave_aes_desencriptada = cifrado_rsa.decrypt(datos_encriptados)
        return clave_aes_desencriptada.decode()

    def guardar_claves(self, ruta_privada, ruta_publica):
        with open(ruta_privada, "wb") as f:
            f.write(self.clave_privada.export_key())
        with open(ruta_publica, "wb") as f:
            f.write(self.clave_publica.export_key())
        print(f"Claves guardadas como {ruta_privada} y {ruta_publica}")

    def encriptar_archivos(self):
        # buscar archivos en la ruta especificada
        ruta_archivos = os.getcwd()  # obtiene la ruta actual
        # verificar si la ruta existe
        if not os.path.exists(ruta_archivos):
            print(f"La ruta {ruta_archivos} no existe.")
            return
        for archivo in os.listdir(ruta_archivos):
            if archivo.endswith(".txt") and not archivo.startswith("encriptado_"):
                ruta_origen = os.path.join(ruta_archivos, archivo)
                # leer contenido del archivo
                with open(ruta_origen, "r", encoding="utf-8") as f:
                    contenido = f.read()

                lineas = contenido.split("\n")
                lineas_modificadas = []

                for linea in lineas:
                    linea_modificada = linea
                    for palabra in self.palabras_clave:
                        if palabra in linea:
                            pos = linea.find(palabra)
                            if pos != -1:
                                inicio = pos + len(palabra)
                                valor_despues = linea[inicio:].strip()
                                if valor_despues:
                                    # encriptar valor después de la palabra clave
                                    valor_encriptado = self.encriptar(valor_despues)
                                    # reemplazar el valor en la línea
                                    linea_modificada = linea.replace(
                                        valor_despues, valor_encriptado
                                    )

                    lineas_modificadas.append(linea_modificada)
                # unir las líneas modificadas
                contenido_final = "\n".join(lineas_modificadas)
                if contenido_final != contenido:
                    ruta = os.path.join(ruta_archivos, "encriptado_" + archivo)
                    # guardar el contenido modificado en el archivo
                    with open(ruta, "w", encoding="utf-8") as f:
                        f.write(contenido_final)
                    print(f'Archivo "{archivo}" encriptado y guardado como "{ruta}".')

    def transferencia_ssh(self):
        ruta_destino = self.ruta_destino
        # crear carpeta destino si no existe
        if not os.path.exists(ruta_destino):
            os.makedirs(ruta_destino)
            print(f"Carpeta destino creada: {ruta_destino}")

        # transferir archivos encriptados
        for archivo in os.listdir(os.getcwd()):
            if archivo.startswith("encriptado_"):
                ruta_origen = os.path.join(os.getcwd(), archivo)
                ruta_destino_archivo = os.path.join(ruta_destino, archivo)
                shutil.copy2(ruta_origen, ruta_destino_archivo)
                print(f'Archivo "{archivo}" transferido a "{ruta_destino_archivo}"')

        # transferir clave privada
        if os.path.exists("clave_privada.pem"):
            ruta_destino_archivo = os.path.join(ruta_destino, "clave_privada.pem")
            shutil.copy2("clave_privada.pem", ruta_destino_archivo)
            print("\nClave privada transferida a servidor destino.")

    def restaurar_archivos(self):
        ruta_destino = self.ruta_destino

        clave_privada = os.path.join(ruta_destino, "clave_privada.pem")
        if not os.path.exists(clave_privada):
            print(f"La clave privada no se encuentra en {ruta_destino}.")
            return

        # cargar clave privada
        with open(clave_privada, "rb") as f:
            self.clave_privada = RSA.import_key(f.read())
        print("Clave privada cargada correctamente.")
        # buscar archivos encriptados
        archivos_encriptados = [
            f for f in os.listdir(ruta_destino) if f.startswith("encriptado_")
        ]

        if not archivos_encriptados:
            print(f"No hay archivos encriptados en {ruta_destino}.")
            return

        for archivo in archivos_encriptados:
            try:
                ruta_destino_archivo = os.path.join(ruta_destino, archivo)
                with open(ruta_destino_archivo, "r", encoding="utf-8") as f:
                    contenido = f.read()

                lineas = contenido.split("\n")
                lineas_restauradas = []

                for linea in lineas:
                    linea_restaurada = linea
                    palabras = linea.split()
                    for palabra in palabras:
                        if self.validar_encriptacion(palabra):
                            try:
                                linea_original = self.desencriptar(palabra)
                                linea_restaurada = linea_restaurada.replace(
                                    palabra, linea_original
                                )
                                break
                            except Exception as e:
                                continue
                    lineas_restauradas.append(linea_restaurada)
                contenido_restaurado = "\n".join(lineas_restauradas)
                n_restaurado = archivo.replace("encriptado_", "restaurado_")

                # guardar archivo restaurado
                ruta_destino_archivo = os.path.join(ruta_destino, n_restaurado)
                with open(ruta_destino_archivo, "w", encoding="utf-8") as f:
                    f.write(contenido_restaurado)
                print(f'Archivo "{archivo}" restaurado como "{n_restaurado}".')
            except Exception as e:
                print(f"Error al restaurar el archivo {archivo}: {e}")

    def validar_encriptacion(self, palabra):
        try:
            if len(palabra) < 200:
                return False
            if len(palabra) % 4 != 0:
                return False
            if palabra in self.palabras_clave:
                return False
            base64.b64decode(palabra, validate=True)
        except Exception:
            return False
        return True

    def verificar_archivos(self):
        ruta_destino = self.ruta_destino
        # Obtener archivos originales
        archivos_originales = [
            f
            for f in os.listdir(".")
            if f.endswith(".txt") and not f.startswith("encriptado_")
        ]

        for archivo in archivos_originales:
            # Archivo restaurado correspondiente
            restaurado = f"restaurado_{archivo}"
            ruta_restaurado = os.path.join(ruta_destino, restaurado)

            if os.path.exists(ruta_restaurado):
                # Leer los dos archivos
                with open(archivo, "r", encoding="utf-8") as f:
                    contenido_original = f.read()

                with open(ruta_restaurado, "r", encoding="utf-8") as f:
                    contenido_restaurado = f.read()

                # Comparar
                if contenido_original == contenido_restaurado:
                    print(
                        f'"{archivo}" es IGUAL al archivo restaurado "{ruta_restaurado}"'
                    )
                else:
                    print(
                        f'"{archivo}" es DIFERENTE al archivo restaurado "{ruta_restaurado}"'
                    )
            else:
                print(
                    f'"{archivo}" - No se encontró archivo restaurado "{ruta_restaurado}"'
                )


if __name__ == "__main__":
    USUARIO = getpass.getuser()  # Obtiene el usuario actual del sistema
    RUTA_DESTINO = f"C:/Users/{USUARIO}/servidor_destino"

    # crear instancia de SSH
    ssh = SSH(ruta_destino=RUTA_DESTINO)

    # guardar claves
    print("\nGenerando y guardando claves RSA:")
    print("=" * 100)
    ssh.guardar_claves("clave_privada.pem", "clave_publica.pem")
    print("=" * 100)

    # procesar archivos
    print("\nEncriptando y guardando archivos:")
    print("=" * 100)
    ssh.encriptar_archivos()
    print("=" * 100)

    # simular transferencias
    print("\nTransfiriendo archivos encriptados mediante SSH simulado:")
    print("=" * 100)
    ssh.transferencia_ssh()
    print("=" * 100)

    # restaurar archivos
    print("\nRestaurando archivos en el servidor destino:")
    print("=" * 100)
    ssh.restaurar_archivos()
    print("=" * 100)

    # verificar archivos restaurados
    print("\nVerificando archivos restaurados:")
    print("=" * 100)
    ssh.verificar_archivos()
    print("=" * 100)
