"""The OpenClaw widget sandbox host, sandbox.<vm_hostname> (controlclaw docs/security-design.md,
"The widget sandbox"): what Caddy serves there, how a claim adds the handle, and the origin OpenClaw
is told.

Run from the repo root: python3 -m unittest tests/test_widget_sandbox.py
"""
import pathlib
import re
import unittest
import urllib.parse

import jinja2

ROLE = pathlib.Path(__file__).resolve().parent.parent / "roles/controlclaw"
HOST = "pool-ab12.ccl.bot"


def render(alias=""):
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(ROLE / "templates")), keep_trailing_newline=True)
    env.filters["urlsplit"] = lambda v, part: getattr(urllib.parse.urlsplit(v), part)
    return env.get_template("Caddyfile.j2").render(
        vm_hostname=HOST, cc_handle_alias=alias, caddy_acme_email="ops@example.com",
        config_api_url="https://controlclaw.com/api/vm-agent/config", browser_novnc_port=6080,
        openclaw_gateway_port=18789, openclaw_sandbox_port=18790, luks_locked_port=3101)


def site(caddyfile, name):
    """The body of one site block, by its first line."""
    start = caddyfile.index(f"\n{name} {{")
    depth, i = 0, caddyfile.index("{", start)
    for j in range(i, len(caddyfile)):
        depth += {"{": 1, "}": -1}.get(caddyfile[j], 0)
        if depth == 0:
            return caddyfile[i + 1:j]
    raise AssertionError("unclosed site block")


class SandboxSite(unittest.TestCase):
    def setUp(self):
        self.sandbox = site(render(), f"sandbox.{HOST}")

    def handle(self, matcher):
        return site("\n" + self.sandbox, f"    handle {matcher}" if matcher else "    handle")

    def test_the_shell_only_after_the_vm_agent_check(self):
        shell = self.handle("@shell")
        self.assertIn("forward_auth 127.0.0.1:3100", shell)
        self.assertIn("uri /__cc/sandbox/verify", shell)
        self.assertLess(shell.index("forward_auth"), shell.index("reverse_proxy 127.0.0.1:18790"))
        self.assertIn("path /mcp-app-sandbox\n", self.sandbox)

    def test_no_cookie_goes_to_openclaw_or_comes_back(self):
        for matcher in ("@shell", "@renderer"):
            body = self.handle(matcher)
            for line in ("header_up -Cookie", "header_up -Authorization", "header_down -Set-Cookie"):
                self.assertIn(line, body, matcher)

    def test_framed_only_by_the_dashboard(self):
        self.assertIn(f'header_down +Content-Security-Policy "frame-ancestors https://{HOST}"', self.handle("@shell"))
        claimed = site(render("mjhtest.ccl.bot"), f"sandbox.{HOST}")
        self.assertIn(f'"frame-ancestors https://{HOST} https://mjhtest.ccl.bot"', claimed)

    def test_public_only_the_two_renderer_bundles_everything_else_404(self):
        self.assertIn("path /__openclaw__/a2ui/a2ui.bundle.js /__openclaw__/a2ui/a2ui-v0.9.bundle.js\n", self.sandbox)
        self.assertNotIn("forward_auth", self.handle("@renderer"))
        self.assertIn("reverse_proxy 127.0.0.1:3100", self.handle("/__cc/sandbox/exchange"))
        self.assertEqual(self.handle("").strip(), "respond 404")
        # Nothing on this host reaches the gateway or the vm-agent's other routes.
        self.assertNotIn("18789", self.sandbox)
        self.assertEqual(len(re.findall(r"reverse_proxy 127\.0\.0\.1:3100", self.sandbox)), 1)


class Claim(unittest.TestCase):
    def test_the_claim_adds_the_handle_to_the_sandbox_ancestors(self):
        # cc-pool-local.cjs edits the rendered Caddyfile by text: the string it looks for is there once.
        pool = render()
        self.assertEqual(pool.count(f'"frame-ancestors https://{HOST}"'), 1)
        script = (ROLE / "files/cc-pool-local.cjs").read_text()
        self.assertIn('const sandboxAncestors = `"frame-ancestors https://${config.hostname}"`;', script)
        self.assertIn('sandboxAncestors, `"frame-ancestors https://${config.hostname} https://${vars.handle_hostname}"`', script)


class OpenClawConfig(unittest.TestCase):
    def test_the_sandbox_origin_is_written_and_checked(self):
        tasks = (ROLE / "tasks/openclaw.yml").read_text()
        self.assertIn("""',"mcp":{"apps":{"sandboxOrigin":"https://sandbox.' ~ vm_hostname ~ '"}}'""", tasks)
        self.assertIn("openclaw_mcp_apps_current.sandboxOrigin | default('') == 'https://sandbox.' ~ vm_hostname", tasks)
        self.assertIn("{{ openclaw_sandbox_json }}}'", tasks)


if __name__ == "__main__":
    unittest.main()
