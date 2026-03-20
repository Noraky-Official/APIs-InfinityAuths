import hashlib
import json
import os
import platform
import subprocess
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class InfinityAuth:
    """
    InfinityAuth Python SDK v3 (Elite Edition)
    Requer: pip install pycryptodome requests
    """

    def __init__(self, name, ownerid, secret, version):
        self.name = name
        self.ownerid = ownerid
        self.secret = secret
        self.version = version
        self.sessionid = None
        self.initialized = False
        self.api_url = "https://infinityauth.shardweb.app/api/InfinityAuth/"

    def init(self):
        """Inicia a sessão com o servidor"""
        response = self._send_request({
            "type": "init",
            "ver": self.version
        })
        
        if response.get("success"):
            self.sessionid = response.get("sessionid")
            self.initialized = True
            return True
        return False

    def login(self, username, password):
        """Realiza login por usuário e senha"""
        return self._send_request({
            "type": "login",
            "username": username,
            "pass": password,
            "hwid": self.get_hwid(),
            "sessionid": self.sessionid
        })

    def register(self, username, password, key):
        """Registra novo usuário usando uma licença"""
        return self._send_request({
            "type": "register",
            "username": username,
            "pass": password,
            "key": key,
            "hwid": self.get_hwid()
        })

    def license(self, key):
        """Login direto usando apenas a chave de licença"""
        return self._send_request({
            "type": "license",
            "key": key,
            "hwid": self.get_hwid()
        })

    def var(self, var_name):
        """Recupera uma variável segura do servidor"""
        return self._send_request({
            "type": "var",
            "var": var_name,
            "sessionid": self.sessionid
        })

    def webhook(self, webhook_name, data=None):
        """Dispara um webhook seguro via servidor"""
        return self._send_request({
            "type": "webhook",
            "webhook": webhook_name,
            "sessionid": self.sessionid,
            "data": data
        })

    def get_hwid(self):
        """Obtém o Hardware ID exclusivo da máquina (Windows)"""
        try:
            if platform.system() != "Windows":
                return platform.node()
            
            cmd = "wmic csproduct get uuid"
            uuid = str(subprocess.check_output(cmd, shell=True))
            return uuid.split(r"\r\r\n")[1].strip()
        except:
            return "unknown-hwid"

    def _send_request(self, params):
        payload = {
            "name": self.name,
            "ownerid": self.ownerid,
            "enc": "1" 
        }

        json_data = json.dumps(params)
        encrypted_data = self._encrypt(json_data, self.secret)
        payload["data"] = encrypted_data

        try:
            response = requests.post(self.api_url, data=payload, timeout=15)
            res_json = response.json()

            if res_json.get("enc") == "1" and res_json.get("data"):
                decrypted = self._decrypt(res_json["data"], self.secret)
                return json.loads(decrypted)
            
            return res_json
        except Exception as e:
            return {"success": False, "message": f"Erro de conexão: {str(e)}"}

    def _encrypt(self, text, key_str):
        key = hashlib.sha256(key_str.encode()).digest()
        iv = os.urandom(16) # IV Dinâmico e aleatório!
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(text.encode(), AES.block_size))
        # Retorna [IV Hex] + [Cipher Hex]
        return iv.hex() + encrypted.hex()

    def _decrypt(self, hex_data, key_str):
        if len(hex_data) < 32:
            raise ValueError("Payload inválido ou corrompido.")
            
        key = hashlib.sha256(key_str.encode()).digest()
        iv_hex = hex_data[:32]
        cipher_hex = hex_data[32:]
        iv = bytes.fromhex(iv_hex)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(bytes.fromhex(cipher_hex)), AES.block_size)
        return decrypted.decode()
