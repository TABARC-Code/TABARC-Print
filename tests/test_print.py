import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from tabarc_print.common import sha256
from tabarc_print.server import Coordinator, Server
from tabarc_print.gateway import FolderGateway, build_job
from tabarc_print.metadata import open_receipt

CLIENT = "client-" + "c" * 40
AGENT = "agent-" + "a" * 40
SECRET = b"a-correct-horse-battery-secret-" + b"a" * 32
PDF = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"

class ServerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.coordinator = Coordinator(Path(self.temp.name), CLIENT, AGENT)
        self.server = Server(("127.0.0.1", 0), self.coordinator)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addr = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.temp.cleanup()

    def request(self, path, role, method="GET", data=None, headers=None):
        h = {"Authorization": "Bearer " + (CLIENT if role == "client" else AGENT)}
        if headers: h.update(headers)
        r = Request(self.addr + path, method=method, data=data, headers=h)
        with urlopen(r, timeout=3) as response:
            return response.status, response.read()

    def test_full_job(self):
        self.request("/v1/agent/register", "agent", "POST", json.dumps({
            "agent_id":"agent1", "printer_id":"laser", "label":"Office Laser"}).encode())
        code, printers = self.request("/v1/printers", "client")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(printers)["printers"][0]["id"], "laser")
        code, response = self.request("/v1/jobs", "client", "POST", PDF,
                                      {"X-Printer-ID": "laser", "X-Filename":"test.pdf"})
        self.assertEqual(code, 201)
        jid = json.loads(response)["id"]
        code, raw = self.request("/v1/agent/claim", "agent", headers={"X-Agent-ID":"agent1"})
        job = json.loads(raw)["job"]
        self.assertEqual(job["id"], jid)
        _, document = self.request("/v1/agent/document/" + jid, "agent", headers={"X-Agent-ID":"agent1"})
        self.assertEqual(document, PDF)
        code, _ = self.request("/v1/agent/complete/" + jid, "agent", "POST",
                json.dumps({"agent_id":"agent1", "success":True,"message":"spooled"}).encode())
        self.assertEqual(code, 200)
        _, jobs = self.request("/v1/jobs", "client")
        self.assertEqual(json.loads(jobs)["jobs"][0]["state"], "submitted")
        self.assertFalse((Path(self.temp.name)/"documents"/(jid+".bin")).exists())

    def test_unauthorised_and_unknown_printer(self):
        with self.assertRaises(HTTPError) as caught:
            urlopen(self.addr + "/v1/jobs", timeout=3)
        self.assertEqual(caught.exception.code, 401)
        with self.assertRaises(HTTPError) as caught:
            self.request("/v1/jobs", "client", "POST", PDF, {"X-Printer-ID":"other"})
        self.assertEqual(caught.exception.code, 400)

    def test_agent_dry_run_full_trip(self):
        from tabarc_print.agent import Agent
        self.coordinator.register("agent1", "office", "Office Printer")
        jid = self.coordinator.submit("office", "test.pdf", PDF)
        a = Agent(self.addr, AGENT, "agent1", {"office": "localqueue"}, dry_run=True)
        self.assertTrue(a.once())
        self.assertEqual(self.coordinator.jobs()[0]["state"], "submitted")
        self.assertEqual(self.coordinator.jobs()[0]["error"], "DRY_RUN")

    def test_wrong_agent_not_allowed(self):
        c = self.coordinator
        c.register("node1", "room1", "Printer")
        j = c.submit("room1", "x.pdf", PDF)
        self.assertIsNone(c.claim("node2"))
        self.assertEqual(c.claim("node1")["id"], j)
        with self.assertRaises(ValueError):
            c.document(j, "node2")
        with self.assertRaises(ValueError):
            c.complete(j, "node2", True, "")

class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.pdf = self.folder / "my.pdf"
        self.pdf.write_bytes(PDF)
        self.receiver = FolderGateway(self.folder / "sync", {"office":"localqueue"}, SECRET, dry_run=True, state_dir=self.folder / "state", allow_direct_submission=True)

    def tearDown(self): self.temp.cleanup()

    def test_signed_handoff_and_replay(self):
        jid = build_job(self.folder / "sync", self.pdf, "office", SECRET)
        self.assertEqual(self.receiver.process_one(jid), "submitted")
        receipt = open_receipt(SECRET, jid, (self.folder / "sync" / "receipts" / (jid+".receipt.bin")).read_bytes())
        self.assertEqual(receipt["message"], "DRY_RUN")
        self.assertEqual(self.receiver.process_one(jid), "duplicate")
        self.assertFalse((self.folder / "sync" / "inbox" / (jid+".bin")).exists())

    def test_tamper_rejected(self):
        jid = build_job(self.folder / "sync", self.pdf, "office", SECRET)
        (self.folder / "sync" / "inbox" / (jid+".bin")).write_bytes(PDF+b"evil")
        self.assertIn("integrity", self.receiver.process_one(jid))

    def test_bad_key_and_age_rejected(self):
        jid = build_job(self.folder / "sync", self.pdf, "office", b"b"*40)
        self.assertIn("authentication", self.receiver.process_one(jid))
        jid2 = build_job(self.folder / "sync", self.pdf, "office", SECRET, at=1)
        self.assertIn("Expired", self.receiver.process_one(jid2))

if __name__ == "__main__":
    unittest.main()
