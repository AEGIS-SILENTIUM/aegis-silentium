"""
AEGIS-SILENTIUM v12 — Python package setup.

Install in development mode:
    pip install -e .

Install for deployment:
    pip install .
"""
from setuptools import setup, find_packages

setup(
    name="aegis-silentium",
    version="12.0.0",
    description="AEGIS-SILENTIUM v12 — Advanced Command & Control Platform",
    python_requires=">=3.11",
    packages=find_packages(exclude=["tests", "tests.*"]),
    install_requires=[
        "Flask>=3.0",
        "PyJWT>=2.9",
        "cryptography>=43",
        "psycopg2-binary>=2.9",
        "redis>=5.1",
        "requests>=2.32",
        "aiohttp>=3.10",
        "prometheus-client>=0.21",
        "structlog>=24",
        "Flask-Cors>=5",
        "Flask-Limiter>=3.8",
        "PyYAML>=6.0",
        "APScheduler>=3.10",
    ],
    entry_points={
        "console_scripts": [
            "aegis-c2=c2.app:main",
            "aegis-node=node.app:main",
            "aegis-scheduler=scheduler.app:main",
        ],
    },
    package_dir={
        "": ".",
    },
    classifiers=[
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
