from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="fibcrypt",
    version="1.1.2",
    description="A fast Fibonacci-based cryptographic toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Hakan Damar",
    author_email="hakan.damar@linux.com",
    packages=find_packages(),
    install_requires=[
        "pycryptodomex>=3.22.0"
    ],
    extras_require={
        "gmpy2": ["gmpy2>=2.1.0"],
    },
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security :: Cryptography"
    ],
)
