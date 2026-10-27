"""Auto-discovers plugins in this package."""
import importlib
import pkgutil
from pathlib import Path
from .base import BasePlugin


def discover() -> dict:
    plugins = {}
    pkg_dir = Path(__file__).parent
    for _, mod_name, _ in pkgutil.iter_modules([str(pkg_dir)]):
        if mod_name in ("base", "registry", "__init__"):
            continue
        try:
            mod = importlib.import_module(f".{mod_name}", package=__package__)
            for attr in dir(mod):
                obj = getattr(mod, attr)
                if isinstance(obj, type) and issubclass(obj, BasePlugin) and obj is not BasePlugin:
                    plugins[obj.name] = obj()
        except Exception as e:
            print(f"Error loading plugin {mod_name}: {e}")
    return plugins