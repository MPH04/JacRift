"""Legacy campaign documents remain readable."""

import unittest

from jrlib.compat import load_campaign_state


class CompatTests(unittest.TestCase):
    def test_vectorrift_state_loads_as_jacrift(self):
        loaded = load_campaign_state({"schema": "vectorrift.state.v1", "campaign": {"status": "complete"}})
        self.assertEqual(loaded["schema"], "jacrift.state.v2")
        self.assertEqual(loaded["compat_from"], "vectorrift.state.v1")
        self.assertEqual(loaded["campaign"]["status"], "complete")

    def test_current_schema_passes_through(self):
        loaded = load_campaign_state({"schema": "jacrift.state.v2", "campaign": {}})
        self.assertEqual(loaded["schema"], "jacrift.state.v2")
        self.assertNotIn("compat_from", loaded)


if __name__ == "__main__":
    unittest.main()
