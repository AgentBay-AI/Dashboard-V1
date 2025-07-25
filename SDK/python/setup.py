from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="hr-agent-sdk",
    version="1.0.0",
    author="AI-HR-Agent Team",
    author_email="contact@ai-hr-agent.com",
    description="Python SDK for AI Agent Operations Platform - Track performance, health, and costs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-repo/ai-hr-agent",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "psutil>=5.9.0",
        "typing-extensions>=4.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=0.991",
        ],
    },
    keywords="ai, agents, monitoring, analytics, performance, health, cost-tracking",
    project_urls={
        "Bug Reports": "https://github.com/your-repo/ai-hr-agent/issues",
        "Source": "https://github.com/your-repo/ai-hr-agent",
        "Documentation": "https://docs.ai-hr-agent.com",
    },
) 