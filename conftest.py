"""
conftest.py — pytest configuration for AEGIS-SILENTIUM v12

Sets up import paths so all test files can import c2.*, node.*, and shared.*
without requiring sys.path.insert() calls in every test file.
"""
import sys
import os

# Add package roots to path
_repo_root = os.path.dirname(os.path.abspath(__file__))
for sub in ["c2", "node", "."]:
    p = os.path.join(_repo_root, sub)
    if p not in sys.path:
        sys.path.insert(0, p)
