#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="vault-agent-sdk",
    version="1.0.0",
    author="Vault Agent Team",
    author_email="support@vault-agent.com",
    description="Official Python SDK for Vault Agent",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/vault-agent/python-sdk",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pre-commit>=3.0.0",
        ],
        "cloud": [
            "boto3>=1.26.0",
            "azure-identity>=1.12.0",
            "azure-keyvault-secrets>=4.7.0",
            "google-cloud-secret-manager>=2.16.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "vault-agent-cli=vault_agent_sdk.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)