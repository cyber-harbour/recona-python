#!/usr/bin/env python3
import pathlib

from setuptools import find_packages, setup

here = pathlib.Path(__file__).parent.resolve()

long_description = (here / "README.md").read_text(encoding="utf-8")

setup(
    name="recona-python",
    version="1.0.0",
    description="Python wrapper for recona.io",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Miltech",
    author_email="roman.romanov@miltech.dev",
    url="https://github.com/cyber-harbour/recona-python",
    license="MIT",
    packages=find_packages(exclude=["tests", "examples"]),
    install_requires=[
        "requests==2.32.4",
        "dataclasses-json~=0.5.4",
        "responses~=0.13.3",
        "limiter~=0.1.2",
    ],
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
