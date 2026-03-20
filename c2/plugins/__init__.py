"""
c2/plugins/__init__.py
AEGIS-SILENTIUM v12 — Plugin Engine
"""
from .engine import PluginEngine, PluginManifest, PluginStatus, PluginHook

__all__ = ["PluginEngine", "PluginManifest", "PluginStatus", "PluginHook"]
