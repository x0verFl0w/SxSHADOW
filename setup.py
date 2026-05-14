from setuptools import setup, find_packages

setup(
    name="sxshadow",
    version="1.0.0",
    description="SxSHADOW — Component Store Hijack Automated Discovery & Weaponization",
    long_description=(
        "Automated enumeration of DLL hijack candidates in the Windows Component "
        "Store (WinSxS), with static PE import analysis, KnownDLLs filtering, "
        "composite scoring, and proxy DLL generation."
    ),
    packages=find_packages(),
    install_requires=[
        "pefile>=2023.2.7",
        "rich>=13.0.0",
        "jinja2>=3.1.0",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "sxshadow=sxshadow:main",
            "wraith=sxshadow:main",      # legacy alias
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: Microsoft :: Windows",
    ],
)
