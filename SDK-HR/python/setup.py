from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="hr-agent-sdk",
    version="0.1.0",
    author="AI HR Agent Team",
    author_email="support@hr-agent.com",
    description="Python SDK for tracking AI agent performance, health, and cost",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/ai-hr-agent",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.0",
        "psutil>=5.8.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "flake8>=3.9.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "hr-agent-sdk=hr_agent_sdk.cli:main",
        ],
    },
) 