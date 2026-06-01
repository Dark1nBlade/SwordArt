from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseConnector(ABC):
    @abstractmethod
    def get_config(self) -> str:
        pass

class FileConnector(BaseConnector):
    def __init__(self, filepath: str):
        self.filepath = filepath

    def get_config(self) -> str:
        with open(self.filepath, 'r') as f:
            return f.read()

class SSHConnector(BaseConnector):
    def __init__(self, host, user, password=None, key_filename=None, port=22):
        self.host = host
        self.user = user
        self.password = password
        self.key_filename = key_filename
        self.port = port

    def get_config(self) -> str:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            self.host,
            username=self.user,
            password=self.password,
            key_filename=self.key_filename,
            port=self.port
        )
        stdin, stdout, stderr = client.exec_command('show')
        config = stdout.read().decode('utf-8')
        client.close()
        return config

class APIConnector(BaseConnector):
    def __init__(self, host, user, password, port=443, verify=False):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.verify = verify
        self.session = None

    def login(self):
        import requests
        self.session = requests.Session()
        url = f"https://{self.host}:{self.port}/logincheck"
        payload = {
            'username': self.user,
            'secretkey': self.password
        }
        res = self.session.post(url, data=payload, verify=self.verify)

    def get_config(self) -> str:
        if not self.session:
            self.login()

        # In a real scenario, we might query multiple endpoints and reconstruct a config-like dict,
        # or use the backup endpoint if it provides a plain-text option.
        # For this tool, we'll assume we can get the text representation.
        import requests
        url = f"https://{self.host}:{self.port}/api/v2/monitor/system/config/backup?scope=global"
        res = self.session.get(url, verify=self.verify)
        # Note: If it's binary, this will be mangled. FortiOS API sometimes requires specific headers for text.
        return res.text
