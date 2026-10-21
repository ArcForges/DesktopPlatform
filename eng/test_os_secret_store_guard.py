# SPDX-License-Identifier: AGPL-3.0-only
"""The script side of the OS secret-store test guard (ArcForges-Design 16-testing-strategy section 1, guard items 1 and 4).

A stray ARCFORGES_OS_SECRET_STORE_TESTS must never reach a routine suite: eng/verify_steps.py refuses to run with it, and
eng/verify_local.py removes it from every suite it starts. These tests set the variable only inside this Python process and its
pure helpers (never for a test host or an adapter), so they never reach an OS secret store; the C# negative tests
(OsSecretStoreGuardTests) show that the adapters refuse a routine process that lacks it.
"""
from __future__ import annotations

import os
import subprocess
import stat
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

import os_secret_store_tier
import verify_local

ROOT = Path(__file__).resolve().parent.parent
OPT_IN = "ARCFORGES_OS_SECRET_STORE_TESTS"
TIER_PROJECT = "tests/OsSecretStoreTests/ArcForges.Tests.OsSecretStoreTests.csproj"


class Step:
    """The Step that eng/verify.py injects into the step table, reduced to what these tests read."""

    def __init__(self, step_id, host, cmd, **options):
        self.id, self.host, self.cmd, self.options = step_id, host, cmd, options


def load_step_table() -> types.ModuleType:
    module = types.ModuleType("verify_steps_under_test")
    module.__dict__["Step"] = Step
    source = (ROOT / "eng/verify_steps.py").read_text(encoding="utf-8")
    exec(compile(source, "eng/verify_steps.py", "exec"), module.__dict__)  # noqa: S102 - the repository's own step table
    return module


def without_opt_in() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key != OPT_IN}


class StepTableRefusesTheOptIn(unittest.TestCase):
    def test_the_pre_push_verification_refuses_to_run_while_the_opt_in_is_present(self):
        for value in ("1", "", "0", "true"):
            with self.subTest(value=value), mock.patch.dict(os.environ, {OPT_IN: value}):
                with self.assertRaises(SystemExit) as refused:
                    load_step_table()
                message = str(refused.exception.code)
                self.assertTrue(message.startswith("arcforges-verify: FAIL " + OPT_IN + " is set"), message)
                self.assertIn("refuses to run", message)

    def test_without_the_opt_in_the_table_loads_and_runs_this_guard_and_never_the_tier(self):
        with mock.patch.dict(os.environ, without_opt_in(), clear=True):
            table = load_step_table()
        ids = [step.id for step in table.STEPS]
        self.assertIn("secret-store-guard-tests", ids)
        for step in table.STEPS:
            command = step.cmd if isinstance(step.cmd, str) else " ".join(step.cmd)
            self.assertNotIn("OsSecretStoreTests", command, step.id)
            self.assertNotIn("os_secret_store_tier", command, step.id)


class RoutineSuitesNeverInheritTheOptIn(unittest.TestCase):
    def test_the_routine_environment_drops_only_the_opt_in(self):
        self.assertEqual({"A": "b"}, verify_local.routine_env({"A": "b", OPT_IN: "1"}))
        with mock.patch.dict(os.environ, {OPT_IN: "1", "ARCFORGES_VERIFY": "1"}):
            routine = verify_local.routine_env()
            self.assertNotIn(OPT_IN, routine)
            self.assertEqual("1", routine["ARCFORGES_VERIFY"])
            self.assertIn(OPT_IN, os.environ)  # the caller's environment is left as it is

    def test_every_suite_and_command_started_with_the_opt_in_present_runs_without_it(self):
        seen = []

        def fake_run(argv, **options):
            seen.append((argv, options.get("env")))
            return subprocess.CompletedProcess(argv, 0, stdout="")

        with mock.patch.dict(os.environ, {OPT_IN: "1"}), mock.patch.object(verify_local.subprocess, "run", fake_run):
            verify_local.test_suite("security-tests", "src/Example/Tests/Example.Tests.csproj")
            verify_local.test_suite(None, "tests/Example/Example.csproj")
            verify_local.run(["dotnet", "--info"])
            verify_local.run(["dotnet", "--info"], env={"PATH": "x", OPT_IN: "1"})
        self.assertEqual(4, len(seen))
        for argv, env in seen:
            self.assertIsNotNone(env, argv)
            self.assertNotIn(OPT_IN, env, argv)
        self.assertEqual(["dotnet", "test", "--project", "src/Example/Tests/Example.Tests.csproj"], seen[0][0][:4])

    def test_a_real_child_of_a_routine_command_does_not_see_the_opt_in(self):
        probe = [sys.executable, "-c", f"import os, sys; sys.exit(7 if {OPT_IN!r} in os.environ else 0)"]
        with mock.patch.dict(os.environ, {OPT_IN: "1"}):
            self.assertEqual(7, subprocess.run(probe, env=dict(os.environ)).returncode)  # the probe itself works
            verify_local.run(probe)  # raises Failure if the child saw the opt-in

    def test_the_step_runner_removes_a_stray_opt_in_before_any_command(self):
        observed = []
        with mock.patch.dict(os.environ, {OPT_IN: "1"}), \
                mock.patch.object(verify_local, "command_hooks", lambda _: observed.append(OPT_IN in os.environ)), \
                mock.patch.object(sys, "argv", ["verify_local.py", "hooks"]):
            self.assertEqual(0, verify_local.main())
        self.assertEqual([False], observed)

    def test_no_routine_suite_is_the_tier(self):
        projects = [project for _, project in verify_local.suites()]
        self.assertTrue(projects)
        self.assertNotIn(TIER_PROJECT, projects)
        self.assertNotIn(TIER_PROJECT, verify_local.TIMING_SENSITIVE)
        self.assertNotIn(TIER_PROJECT, verify_local.ARCHITECTURE)


class TierRunnerRunsOnlyOnTheExplicitOptIn(unittest.TestCase):
    def test_without_the_exact_opt_in_the_tier_is_reported_as_not_run(self):
        for environ in ({}, {OPT_IN: ""}, {OPT_IN: "true"}, {OPT_IN: " 1"}):
            with self.subTest(environ=environ):
                code, message = os_secret_store_tier.refusal(environ, "win32")
                self.assertEqual(os_secret_store_tier.NOT_RUN, code)
                self.assertTrue(message.startswith("NOT RUN"), message)

    def test_linux_runs_only_on_the_isolated_test_host(self):
        # A WSL distribution name no longer admits the tier (AD-0019 section 6); only the isolated host's marker does.
        for distribution in (None, "Debian", "ArcForgesTest"):
            environ = {OPT_IN: "1"} | ({"WSL_DISTRO_NAME": distribution} if distribution else {})
            with self.subTest(distribution=distribution):
                code, message = os_secret_store_tier.refusal(environ, "linux")
                self.assertEqual(1, code)
                self.assertIn(str(os_secret_store_tier.ISOLATED_HOST_MARKER), message)
        self.assertIsNone(os_secret_store_tier.refusal({OPT_IN: "1"}, "linux", isolated=True))
        self.assertEqual(os_secret_store_tier.NOT_RUN, os_secret_store_tier.refusal({}, "linux", isolated=True)[0])
        self.assertIsNone(os_secret_store_tier.refusal({OPT_IN: "1"}, "win32"))
        self.assertEqual(1, os_secret_store_tier.refusal({OPT_IN: "1"}, "darwin")[0])

    def test_the_marker_counts_only_as_a_root_owned_regular_file_in_a_root_owned_directory(self):
        marker = Path("/etc/arcforges/isolated-secret-store-test-host")
        directory, regular, link = stat.S_IFDIR | 0o755, stat.S_IFREG | 0o644, stat.S_IFLNK | 0o777

        def check(entries, euid=1000):
            def lstat(path):
                if str(path) not in entries:
                    raise FileNotFoundError(path)
                mode, uid = entries[str(path)]
                return types.SimpleNamespace(st_mode=mode, st_uid=uid)
            return os_secret_store_tier.isolated_host(marker, lstat=lstat, geteuid=lambda: euid)

        good = {"/etc/arcforges": (directory, 0), str(marker): (regular, 0)}
        self.assertTrue(check(good))
        for name, entries, euid in (
                ("missing marker", {"/etc/arcforges": (directory, 0)}, 1000),
                ("missing directory", {}, 1000),
                ("run as root", good, 0),
                ("symbolic link", good | {str(marker): (link, 0)}, 1000),
                ("a directory", good | {str(marker): (directory, 0)}, 1000),
                ("not owned by root", good | {str(marker): (regular, 1000)}, 1000),
                ("group-writable", good | {str(marker): (regular | stat.S_IWGRP, 0)}, 1000),
                ("world-writable", good | {str(marker): (regular | stat.S_IWOTH, 0)}, 1000),
                ("directory not owned by root", good | {"/etc/arcforges": (directory, 1000)}, 1000),
                ("directory writable by others", good | {"/etc/arcforges": (directory | stat.S_IWOTH, 0)}, 1000)):
            with self.subTest(name):
                self.assertFalse(check(entries, euid))

    def test_the_runner_runs_exactly_the_tier_project(self):
        self.assertEqual(["dotnet", "test", "--project", TIER_PROJECT, "-c", "Release", "--no-build"],
                         os_secret_store_tier.test_command()[:7])
        self.assertEqual(["dotnet", "build", TIER_PROJECT, "-c", "Release"], os_secret_store_tier.build_command())

    def test_without_the_opt_in_main_runs_nothing(self):
        with mock.patch.dict(os.environ, without_opt_in(), clear=True), \
                mock.patch.object(os_secret_store_tier.subprocess, "run", side_effect=AssertionError("ran a command")), \
                mock.patch.object(sys, "argv", ["os_secret_store_tier.py"]):
            self.assertEqual(os_secret_store_tier.NOT_RUN, os_secret_store_tier.main())


if __name__ == "__main__":
    unittest.main()
