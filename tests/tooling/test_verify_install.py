# SPDX-License-Identifier: Apache-2.0
"""Tests for `python eng/verify.py install` (standard library unittest)."""
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
POSIX = os.name != "nt"


def load_verify():
    spec = importlib.util.spec_from_file_location("arcforges_verify", ROOT / "eng" / "verify.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve the module of their annotations
    spec.loader.exec_module(module)
    return module


def clean_env() -> dict[str, str]:
    """An environment in which git sees only the temporary clone: no variables of a hook or verification checkout that
    runs these tests, and no global or system configuration (whose core.hooksPath install would rightly refuse)."""
    local = subprocess.run(["git", "rev-parse", "--local-env-vars"], capture_output=True, text=True).stdout.split()
    env = {name: value for name, value in os.environ.items() if name not in local}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    return env


class InstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = clean_env()
        self.clone = Path(tempfile.mkdtemp(prefix="arcforges-verify-install-"))
        self.addCleanup(shutil.rmtree, self.clone, ignore_errors=True)
        subprocess.run(["git", "init", "--quiet", str(self.clone)], check=True, env=self.env)
        (self.clone / "eng").mkdir()
        shutil.copy2(ROOT / "eng" / "verify.py", self.clone / "eng" / "verify.py")
        shutil.copytree(ROOT / ".githooks", self.clone / ".githooks")
        # A checkout without the executable bit (core.fileMode false, an archive, a Windows checkout) must not matter.
        for hook in (self.clone / ".githooks").iterdir():
            hook.chmod(0o644)
        self.hook = self.clone / ".git" / "hooks" / "pre-push"

    def install(self) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(self.clone / "eng" / "verify.py"), "install"], cwd=self.clone,
                              env=self.env, capture_output=True, text=True, encoding="utf-8", errors="replace")

    def assert_installed(self, result: subprocess.CompletedProcess) -> None:
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.hook.read_bytes(), (ROOT / ".githooks" / "pre-push").read_bytes().replace(b"\r\n", b"\n"))

    def test_installs_the_hook(self) -> None:
        self.assert_installed(self.install())

    @unittest.skipUnless(POSIX, "Windows has no executable bit; git for Windows runs the hook regardless")
    def test_installed_hook_is_executable(self) -> None:
        self.assert_installed(self.install())
        mode = self.hook.stat().st_mode
        self.assertEqual(mode & 0o755, 0o755, oct(mode))
        self.assertTrue(os.access(self.hook, os.X_OK))

    @unittest.skipUnless(POSIX, "Windows has no executable bit; git for Windows runs the hook regardless")
    def test_reinstall_makes_an_existing_non_executable_hook_executable(self) -> None:
        # A clone installed by the earlier script holds the hook with mode 0644, which git ignores; installing again
        # (write_bytes keeps an existing file's mode) must repair it.
        self.hook.parent.mkdir(exist_ok=True)
        self.hook.write_bytes((ROOT / ".githooks" / "pre-push").read_bytes())
        self.hook.chmod(0o644)
        self.assert_installed(self.install())
        self.assertTrue(os.access(self.hook, os.X_OK))

    @unittest.skipUnless(POSIX, "Windows has no executable bit; git for Windows runs the hook regardless")
    def test_install_fails_when_the_hook_stays_non_executable(self) -> None:
        verify = load_verify()
        repo = SimpleNamespace(top=self.clone, common=self.clone / ".git")
        with mock.patch.dict(os.environ, self.env, clear=True), \
                mock.patch.object(verify.os, "access", return_value=False), redirect_stdout(StringIO()):
            with self.assertRaisesRegex(verify.VerifyError, "not executable"):
                verify.command_install(repo)


if __name__ == "__main__":
    unittest.main()
