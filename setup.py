import os

from setuptools import find_packages, setup
from setuptools.dist import Distribution


class BinaryDistribution(Distribution):
    def has_ext_modules(self):
        return True


# Read the contents of README.md for the long project description
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="alkindi",
    version="0.1.3",
    description="A Python library for post-quantum cryptographic algorithms",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Khalid Alraddady",
    url="https://github.com/alraddady/alkindi",
    license="LGPL-3.0-or-later",
    packages=find_packages("src"),
    package_dir={"": "src"},
    include_package_data=True,
    setup_requires=["setuptools>=70", "cffi>=1.15"],
    install_requires=["cffi>=1.15"],
    cffi_modules=["src/alkindi/bindings.py:ffi"],
    extras_require={
        "dev": ["pytest"],
    },
    zip_safe=False,
    distclass=BinaryDistribution,
    python_requires=">=3.10",
)
