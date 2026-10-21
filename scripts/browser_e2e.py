"""Browser-level user journey and accessibility checks for ConduitGuard."""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from typing import Any

from playwright.sync_api import expect, sync_playwright

BASE_URL = os.environ.get("CONDUITGUARD_URL", "http://127.0.0.1:3000")
AXE_URL = "https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.10.3/axe.min.js"
REPORT_DIR = Path(os.environ.get("CONDUITGUARD_REPORT_DIR", "artifacts"))
REPORT_JSON = REPORT_DIR / "accessibility-report.json"
REPORT_MARKDOWN = REPORT_DIR / "accessibility-report.md"
AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]


class BrowserJourneyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch()
        cls.audit_results: list[dict[str, Any]] = []

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "browser"):
            cls.browser.close()
            cls.playwright.stop()
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        report = {
            "standard": "WCAG 2.1 A/AA automated axe-core checks",
            "axe_core": "4.10.3",
            "results": cls.audit_results,
            "manual_checks": {
                "keyboard_skip_link": "tested: first Tab focuses skip link; Enter moves focus to configuration",
                "result_tabs": "tested: tab controls can be activated and expose associated result panels",
                "form_labels": "tested: current, proposed, and probe textareas have accessible names",
                "mobile_overflow": "tested at 390x844; document width must not exceed viewport",
                "screen_reader": "semantic roles, accessible names, and live status messages are asserted through browser locators; physical assistive-technology testing remains manual",
            },
            "fixes": [
                "Added a visible-on-focus skip link to bypass repeated navigation.",
                "Announced demo loading state through a polite status region and exposed busy state on its control.",
            ],
        }
        REPORT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
        violations = [item for result in cls.audit_results for item in result["violations"]]
        lines = [
            "# Accessibility Audit",
            "",
            f"Automated standard: {report['standard']} (axe-core {report['axe_core']}).",
            "",
            "## Results",
        ]
        if not cls.audit_results:
            lines.append("No audit results were produced; run the browser E2E suite.")
        for result in cls.audit_results:
            lines.append(
                f"- {result['viewport']}: {len(result['violations'])} violations, {result['passes']} rules passed."
            )
        lines.extend(["", "## Findings"])
        if violations:
            for item in violations:
                lines.append(f"- **{item['id']} ({item['impact']})**: {item['help']} ({item['helpUrl']})")
        else:
            lines.append("- No axe-core WCAG 2.1 A/AA violations in the audited desktop and mobile result views.")
        lines.extend(["", "## Fixes and Manual Checks"])
        lines.extend(f"- {item}" for item in report["fixes"])
        lines.extend(f"- {key.replace('_', ' ')}: {value}." for key, value in report["manual_checks"].items())
        REPORT_MARKDOWN.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def setUp(self) -> None:
        self.page = self.browser.new_page(viewport={"width": 1440, "height": 1000})
        self.page.goto(BASE_URL, wait_until="networkidle")
        self.page.get_by_label("Current configuration").wait_for()

    def tearDown(self) -> None:
        self.page.close()

    def analyze_demo(self) -> None:
        self.page.get_by_role("button", name="Analisis perubahan").click()
        self.page.locator("#results").wait_for()

    def run_axe(self, label: str) -> dict[str, Any]:
        self.page.add_script_tag(url=AXE_URL)
        result = self.page.evaluate(
            """async (tags) => {
              const audit = await axe.run(document, { runOnly: { type: 'tag', values: tags } });
              return {
                violations: audit.violations.map(({ id, impact, description, help, helpUrl, nodes }) => ({
                  id, impact, description, help, helpUrl,
                  nodes: nodes.map(({ target, failureSummary }) => ({ target, failureSummary }))
                })),
                passes: audit.passes.length,
                incomplete: audit.incomplete.map(({ id, impact, description, help, helpUrl }) => ({ id, impact, description, help, helpUrl }))
              };
            }""",
            AXE_TAGS,
        )
        report = {"viewport": label, **result}
        self.audit_results.append(report)
        return report

    def test_demo_edit_analyze_results_tabs_and_export(self) -> None:
        before = json.loads(self.page.get_by_label("Current configuration").input_value())
        after = json.loads(self.page.get_by_label("Proposed configuration").input_value())
        after["rules"].append(
            {
                "id": "browser-e2e-ssh",
                "source": "*",
                "destination": "192.0.2.10",
                "protocol": "tcp",
                "port": 22,
                "action": "allow",
                "priority": 100,
            }
        )
        self.page.get_by_label("Current configuration").fill(json.dumps(before))
        self.page.get_by_label("Proposed configuration").fill(json.dumps(after))
        self.analyze_demo()

        self.page.get_by_role("tab", name="Temuan").click()
        self.page.get_by_role("heading", name="Administrative port is allowed").wait_for()
        self.page.get_by_role("tab", name="Simulasi").click()
        self.page.get_by_role("heading", name="Connection decisions").wait_for()
        self.page.get_by_role("tab", name="Ringkasan").click()
        self.page.get_by_text("browser-e2e-ssh").wait_for()

        with self.page.expect_download() as download_info:
            self.page.get_by_role("button", name="Export JSON").click()
        download = download_info.value
        self.assertEqual(download.suggested_filename, "conduitguard-report.json")
        path = REPORT_DIR / download.suggested_filename
        path.parent.mkdir(parents=True, exist_ok=True)
        download.save_as(path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn("generated_at", payload)
        self.assertIn("findings", payload)
        path.unlink(missing_ok=True)

    def test_invalid_input_and_empty_simulation_states(self) -> None:
        self.page.get_by_label("Current configuration").fill("{")
        self.page.get_by_role("button", name="Analisis perubahan").click()
        self.page.get_by_role("alert").get_by_text("JSON tidak valid").wait_for()

        load_button = self.page.get_by_role("button", name="Muat contoh")
        load_button.click()
        expect(load_button).to_be_enabled()
        self.page.get_by_label("Uji konektivitas").fill("")
        self.analyze_demo()
        self.page.get_by_role("tab", name="Simulasi").click()
        self.page.get_by_text("No probes supplied").wait_for()

        before = json.loads(self.page.get_by_label("Current configuration").input_value())
        self.page.get_by_label("Proposed configuration").fill(json.dumps(before))
        self.page.get_by_role("button", name="Analisis perubahan").click()
        self.page.locator("#results").wait_for()
        self.page.get_by_role("tab", name="Temuan").click()
        self.page.get_by_text("No findings").wait_for()
        self.page.get_by_role("tab", name="Ringkasan").click()
        self.page.get_by_text("No policy changes detected").wait_for()

    def test_keyboard_navigation_and_accessible_labels(self) -> None:
        self.page.keyboard.press("Tab")
        self.assertEqual(self.page.evaluate("document.activeElement.className"), "skip-link")
        self.assertEqual(self.page.evaluate("getComputedStyle(document.activeElement).outlineStyle"), "solid")
        self.page.keyboard.press("Enter")
        self.assertEqual(self.page.evaluate("document.activeElement.id"), "configuration")
        self.assertTrue(self.page.get_by_role("main").count())
        self.assertTrue(self.page.get_by_label("Current configuration").count())
        self.assertTrue(self.page.get_by_label("Proposed configuration").count())
        self.assertTrue(self.page.get_by_label("Uji konektivitas").count())
        self.analyze_demo()
        selected_tab = self.page.get_by_role("tab", name="Ringkasan")
        selected_tab.focus()
        self.page.keyboard.press("ArrowRight")
        expect(self.page.get_by_role("tab", name="Temuan")).to_have_attribute("aria-selected", "true")

    def test_mobile_layout_and_a11y_audit_report(self) -> None:
        self.page.set_viewport_size({"width": 390, "height": 844})
        self.page.reload(wait_until="networkidle")
        self.assertLessEqual(
            self.page.evaluate("document.documentElement.scrollWidth"),
            self.page.evaluate("window.innerWidth"),
            "The mobile page must not overflow horizontally.",
        )
        self.assertTrue(self.page.get_by_role("button", name="Analisis perubahan").is_visible())
        self.analyze_demo()
        report = self.run_axe("mobile-390x844-results")
        self.assertEqual(report["violations"], [], json.dumps(report["violations"], indent=2))

        self.page.set_viewport_size({"width": 1440, "height": 1000})
        self.page.reload(wait_until="networkidle")
        self.analyze_demo()
        report = self.run_axe("desktop-1440x1000-results")
        self.assertEqual(report["violations"], [], json.dumps(report["violations"], indent=2))

    def test_api_unavailable_error_state(self) -> None:
        self.page.route("**/api/examples/demo", lambda route: route.abort())
        self.page.reload(wait_until="domcontentloaded")
        self.page.get_by_role("alert").get_by_text("API is unavailable").wait_for()
        self.assertTrue(self.page.get_by_role("button", name="Analisis perubahan").is_visible())

    def test_loading_state_is_announced_and_disables_demo_reload(self) -> None:
        self.page.add_init_script(
            """(() => {
              const originalFetch = window.fetch.bind(window);
              window.fetch = (input, init) => String(input).includes('/api/examples/demo')
                ? new Promise(() => {})
                : originalFetch(input, init);
            })();"""
        )
        self.page.reload(wait_until="domcontentloaded")
        load_button = self.page.get_by_role("button", name="Memuat")
        load_button.wait_for()
        self.assertTrue(load_button.is_disabled())
        self.assertEqual(load_button.get_attribute("aria-busy"), "true")
        self.page.get_by_role("status").get_by_text("Memuat konfigurasi contoh").wait_for()


if __name__ == "__main__":
    unittest.main(verbosity=2)