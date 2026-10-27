"""Plugin SDK base class."""
from abc import ABC, abstractmethod


class BasePlugin(ABC):
    name = "base"
    technique = "unknown"

    @abstractmethod
    def run(self, target: str, **kwargs) -> dict:
        """
        Execute the plugin against a target.
        Must return a dict with at least: {'target', 'findings', 'raw'}
        """
        raise NotImplementedError