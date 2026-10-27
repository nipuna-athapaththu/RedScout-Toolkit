"""YAML-driven workflow engine."""
import yaml
from pathlib import Path


class WorkflowEngine:
    def __init__(self, plugins: dict):
        self.plugins = plugins

    def load(self, path: str) -> dict:
        return yaml.safe_load(Path(path).read_text())

    def run(self, path: str, target: str, guard, audit, vault):
        wf = self.load(path)
        results = []
        previous = {}
        for step in wf["steps"]:
            plugin_name = step["plugin"]
            if plugin_name not in self.plugins:
                audit.log("plugin_missing", plugin=plugin_name)
                continue

            plugin = self.plugins[plugin_name]
            if not guard.is_technique_allowed(plugin.technique):
                audit.log("technique_blocked", technique=plugin.technique)
                continue

            if "condition" in step and not previous.get("findings"):
                audit.log("step_skipped", plugin=plugin_name, reason="condition")
                continue

            audit.log("step_start", plugin=plugin_name, target=target)
            result = plugin.run(target, **step.get("params", {}))
            previous = result
            results.append({"plugin": plugin_name, **result})
            vault.add("finding", target, result["findings"],
                      notes=f"plugin={plugin_name}")
            audit.log("step_done", plugin=plugin_name,
                      findings=len(result.get("findings", [])))
        return results