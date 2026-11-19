import base64
import json
import runpy
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch


module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "fetch-ca.py"))
extract = module["extract"]


def new_certificate():
    return subprocess.check_output([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes", "-keyout", "/dev/null", "-subj", "/CN=Trustee TDVM instance root",
    ], stderr=subprocess.DEVNULL)


class ConsoleCertificateTest(unittest.TestCase):
    def test_interleaved_journal(self):
        pem = new_certificate()
        records = []
        for line in pem.decode().splitlines():
            records.append("2026-11-19 [ 1.234] bash[1273]: " + line)
            records.append("[ 1.235] systemd[1]: done")
            records.append("[ 1.236] other[34]: " + "A" * 64)
        console = "\r\n".join(records)
        self.assertEqual(extract(console), pem)
        self.assertEqual(extract(pem.decode() + console), pem)

    def test_plain_colored_and_truncated_console(self):
        pem = new_certificate()
        self.assertEqual(extract("\x1b[0m" + pem.decode() + "\x1b[0m"), pem)
        with self.assertRaisesRegex(ValueError, "no complete CA"):
            extract(pem.decode().split("-----END")[0])
        with self.assertRaisesRegex(ValueError, "multiple distinct"):
            extract((pem + new_certificate()).decode())

    def test_retry_only_when_no_complete_certificate(self):
        pem = new_certificate()

        def response(contents):
            return json.dumps({"ConsoleOutput": base64.b64encode(contents).decode()}).encode()

        with patch("subprocess.check_output", side_effect=[response(b""), response(pem)]) as cli:
            self.assertEqual(module["fetch"]("region", "instance"), pem)
            self.assertEqual(cli.call_args[0][0][-2:], ["--RemoveSymbols", "true"])
        ambiguous = response(pem + new_certificate())
        with patch("subprocess.check_output", return_value=ambiguous) as cli:
            with self.assertRaisesRegex(ValueError, "multiple distinct"):
                module["fetch"]("region", "instance")
            self.assertEqual(cli.call_count, 1)


if __name__ == "__main__":
    unittest.main()
