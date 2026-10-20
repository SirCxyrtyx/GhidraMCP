import asyncio
import inspect
import unittest
from unittest.mock import Mock, patch

import bridge_mcp_ghidra as bridge


class ProgramTargetingTests(unittest.TestCase):
    def setUp(self):
        self.response = Mock(ok=True, text='{"ok": true}', status_code=200)
        self.response.json.return_value = {"ok": True}

    def test_every_program_tool_exposes_and_forwards_target(self):
        tools = asyncio.run(bridge.mcp.list_tools())
        for tool in tools:
            if tool.name == "list_programs":
                continue
            with self.subTest(tool=tool.name):
                self.assertIn("program", tool.inputSchema["properties"])
                self.assertNotIn("program", tool.inputSchema.get("required", []))
                fn = getattr(bridge, tool.name)
                args = {}
                for name, param in inspect.signature(fn).parameters.items():
                    if param.default is not inspect.Parameter.empty:
                        continue
                    args[name] = {int: 1, list: []}.get(param.annotation, "test")
                with patch.object(bridge.requests, "get", return_value=self.response) as get, \
                     patch.object(bridge.requests, "post", return_value=self.response) as post:
                    fn(**args, program="/folder/A & B+测试.exe")
                    calls = get.call_args_list + post.call_args_list
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(calls[0].kwargs["params"]["program"], "/folder/A & B+测试.exe")

    def test_post_bodies_are_unchanged(self):
        with patch.object(bridge.requests, "post", return_value=self.response) as post:
            bridge.decompile_function("main", program="one.exe")
            self.assertEqual(post.call_args.kwargs["data"], b"main")
            bridge.rename_function("old", "new", program="two.exe")
            self.assertEqual(post.call_args.kwargs["data"], {"oldName": "old", "newName": "new"})
            renames = [{"address": "0x1000", "new_name": "start"}]
            bridge.rename_functions(renames, program="three.exe")
            self.assertEqual(post.call_args.kwargs["json"], renames)
            bridge.run_script("println(currentProgram.getName())", timeout=120, program="one.exe")
            self.assertEqual(post.call_args.kwargs["timeout"], 150)

    def test_target_does_not_leak_to_next_call(self):
        with patch.object(bridge.requests, "get", return_value=self.response) as get:
            bridge.list_methods(program="one.exe")
            bridge.list_methods()
            self.assertNotIn("program", get.call_args.kwargs["params"])
            bridge.list_programs()
            self.assertTrue(get.call_args.args[0].endswith("/list_programs"))
            self.assertEqual(get.call_args.kwargs["params"], {})

    def test_explicit_empty_target_is_not_treated_as_active(self):
        with patch.object(bridge.requests, "get", return_value=self.response) as get:
            bridge.read_memory("0x1000", 4, program="")
            self.assertEqual(get.call_args.kwargs["params"]["program"], "")

    def test_targeting_errors_are_returned(self):
        self.response.ok = False
        self.response.status_code = 400
        self.response.text = '{"error": "Ambiguous program"}'
        self.response.json.return_value = {"error": "Ambiguous program"}
        with patch.object(bridge.requests, "get", return_value=self.response):
            self.assertIn("Ambiguous program", bridge.list_methods(program="same.exe")[0])
            self.assertEqual(bridge.read_memory("0x1000", 4, program="same.exe"),
                             {"error": "Ambiguous program"})


if __name__ == "__main__":
    unittest.main()
