"""An in-memory stand-in for an OS credential vault during isolated tests."""
from unittest.mock import patch
from tabarc_print.secret_store import SecretStore

class TestVault:
    def __init__(self):
        self.values = {}
    def set_password(self, service, name, value):
        self.values[(service,name)] = value
    def get_password(self, service, name):
        return self.values.get((service,name))
    def delete_password(self, service, name):
        self.values.pop((service,name),None)

VAULT = TestVault()

def local_vault_patch():
    return patch('tabarc_print.local_queue.SecretStore',
                 side_effect=lambda root: SecretStore(root, backend=VAULT))
