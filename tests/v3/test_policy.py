import unittest

from sis.v3.policy import ACTIONS, PERMISSIONS, ROLES, AuthorizationDenied, is_allowed, require_permission


class V3PolicyTests(unittest.TestCase):
    def test_agent_can_only_read_qualified_guidance_and_append_observation(self):
        self.assertEqual(PERMISSIONS["agent"], frozenset({
            "guidance:read", "qualified_catalog:read", "observation:append",
        }))
        for action in ACTIONS - PERMISSIONS["agent"]:
            with self.subTest(action=action), self.assertRaises(AuthorizationDenied):
                require_permission("agent", action)

    def test_principals_do_not_cross_sign_or_promote_authorities(self):
        self.assertTrue(is_allowed("evaluator", "outcome:sign"))
        self.assertFalse(is_allowed("operator", "outcome:sign"))
        self.assertTrue(is_allowed("operator", "promotion:approve"))
        self.assertFalse(is_allowed("evaluator", "promotion:approve"))
        self.assertFalse(is_allowed("learner", "qualified_catalog:read"))

    def test_unknown_roles_actions_and_json_style_role_values_fail_closed(self):
        for role, action in (("admin", "promotion:approve"), ("agent", "catalog:write"),
                             (None, "promotion:approve"), ("operator", None)):
            with self.subTest(role=role, action=action):
                self.assertFalse(is_allowed(role, action))
                with self.assertRaises(AuthorizationDenied):
                    require_permission(role, action)

    def test_permission_matrix_is_not_mutable(self):
        self.assertEqual(ROLES, frozenset(PERMISSIONS))
        with self.assertRaises(TypeError):
            PERMISSIONS["agent"] = frozenset({"promotion:approve"})


if __name__ == "__main__":
    unittest.main()
