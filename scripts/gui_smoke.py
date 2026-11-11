"""Short UI smoke run. Execute with a graphical session or xvfb-run."""
import tempfile
import sys
import time
from pathlib import Path
from unittest.mock import patch
import tkinter as tk

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tabarc_print.desktop import DesktopController, DesktopPanel
from tabarc_print.secret_store import SecretStore

class InMemoryVault:
    def __init__(self):
        self.data = {}
    def set_password(self, service, name, value):
        self.data[(service, name)] = value
    def get_password(self, service, name):
        return self.data.get((service, name))
    def delete_password(self, service, name):
        self.data.pop((service, name), None)

vault = InMemoryVault()

with tempfile.TemporaryDirectory() as temp, patch(
        'tabarc_print.local_queue.SecretStore',
        side_effect=lambda directory: SecretStore(directory, backend=vault)):
    root = tk.Tk()
    ctrl = DesktopController(Path(temp) / 'state', backend='cups', auth_dir=Path(temp) / 'auth')
    with patch('tabarc_print.desktop.discover_printers', return_value=['Test printer']):
        panel = DesktopPanel(root, ctrl)
        for _ in range(25):
            root.update()
            time.sleep(0.02)
        assert 'Test printer' in panel.printer_widget['values']
        doc = Path(temp) / 'test.pdf'
        doc.write_bytes(b'%PDF-1.5\n%%EOF')
        job_id = ctrl.submit(doc, 'Test printer', held=True)
        panel.refresh_jobs()
        panel.table.selection_set(job_id)
        panel._update_actions()
        assert panel.actions['Print selected'].instate(['disabled'])
        assert panel.actions['Release'].instate(['!disabled'])
        panel.show_accounts()
        root.update()
        assert panel.accounts_window is not None
        assert panel.accounts_window.winfo_exists()
        assert 'Google' in panel.accounts_window.title() or 'Cloud accounts' in panel.accounts_window.title()
        panel.show_cloud_print()
        root.update()
        assert panel.cloud_window is not None
        assert panel.cloud_window.winfo_exists()
        assert 'Cloud printing' in panel.cloud_window.title()
        assert not ctrl.cloud.profiles.path.exists()
        panel.close()
print('GUI smoke passed')
