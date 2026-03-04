from setuptools import find_packages, setup

setup(
    name="kfuzz",
    version="1.1",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "pwntools",
        "rich",
        "capstone",
        "pyelftools",
    ],
    entry_points={
        "console_scripts": [
            "kfuzz=kfuzz.cli:main",
        ],
    },
)
