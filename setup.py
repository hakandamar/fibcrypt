from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="fibcrypt",
    version="1.2.1",
    description="A fast Fibonacci-based cryptographic toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Hakan Damar",
    author_email="hakan.damar@linux.com",
    url="https://github.com/hakandamar/fibcrypt",
    project_urls={
        "Bug Tracker": "https://github.com/hakandamar/fibcrypt/issues",
        "Documentation": "https://github.com/hakandamar/fibcrypt#readme",
        "Source": "https://github.com/hakandamar/fibcrypt",
        "Security Policy": "https://github.com/hakandamar/fibcrypt/blob/master/SECURITY.md",
    },
    license="MIT",
    packages=find_packages(),
    install_requires=[
        "pycryptodomex>=3.22.0"
    ],
    extras_require={
        "gmpy2": ["gmpy2>=2.1.0"],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography"
    ],
)
