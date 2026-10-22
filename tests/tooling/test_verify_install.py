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
HOOK = "#!/bin/sh\nset -eu\ngit diff --cached --check\n"
# The pre-push hook an earlier eng/verify.py installed.
RETIRED = ('#!/bin/sh\ntop=$(git rev-parse --show-toplevel) || exit 1\n'
           'exec python "$top/eng/verify.py" pre-push "$@"\n')


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
        (self.clone / ".githooks").mkdir()
        # A checkout without the executable bit (core.fileMode false, an archive, a Windows checkout) must not matter.
        (self.clone / ".githooks" / "pre-commit").write_text(HOOK, encoding="utf-8", newline="\n")
        (self.clone / ".githooks" / "pre-commit").chmod(0o644)
        self.hooks = self.clone / ".git" / "hooks"
        self.hook = self.hooks / "pre-commit"

    def install(self) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(self.clone / "eng" / "verify.py"), "install"], cwd=self.clone,
                              env=self.env, capture_output=True, text=True, encoding="utf-8", errors="replace")

    def assert_installed(self, result: subprocess.CompletedProcess) -> None:
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.hook.read_text(encoding="utf-8"), HOOK)

    def test_installs_the_hooks(self) -> None:
        self.assert_installed(self.install())

    def test_removes_the_retired_pre_push_verification_hook(self) -> None:
        self.hooks.mkdir(exist_ok=True)
        (self.hooks / "pre-push").write_text(RETIRED, encoding="utf-8")
        result = self.install()
        self.assert_installed(result)
        self.assertFalse((self.hooks / "pre-push").exists(), result.stdout)
        self.assertIn("removed the retired pre-push verification hook", result.stdout)

    def test_keeps_a_pre_push_hook_it_did_not_install(self) -> None:
        self.hooks.mkdir(exist_ok=True)
        own = "#!/bin/sh\necho mine\n"
        (self.hooks / "pre-push").write_text(own, encoding="utf-8")
        self.assert_installed(self.install())
        self.assertEqual((self.hooks / "pre-push").read_text(encoding="utf-8"), own)

    def test_a_clone_without_hooks_installs_nothing_and_still_retires_the_old_hook(self) -> None:
        shutil.rmtree(self.clone / ".githooks")
        self.hooks.mkdir(exist_ok=True)
        (self.hooks / "pre-push").write_text(RETIRED, encoding="utf-8")
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.hooks / "pre-push").exists())
        self.assertFalse(self.hook.exists())

    @unittest.skipUnless(POSIX, "Windows has no executable bit; git for Windows runs the hook regardless")
    def test_installed_hook_is_executable(self) -> None:
        self.assert_installed(self.install())
        mode = self.hook.stat().st_mode
        self.assertEqual(mode & 0o755, 0o755, oct(mode))
        self.assertTrue(os.access(self.hook, os.X_OK))

    @unittest.skipUnless(POSIX, "Windows has no executable bit; git for Windows runs the hook regardless")
    def test_reinstall_makes_an_existing_non_executable_hook_executable(self) -> None:
        # write_bytes keeps an existing file's mode, so a hook left at 0644 must be repaired by installing again.
        self.hooks.mkdir(exist_ok=True)
        self.hook.write_text(HOOK, encoding="utf-8")
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
