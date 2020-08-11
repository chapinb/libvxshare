"""Installer for libvxshare"""
import setuptools
from libvxshare import __name__, __version__, __desc__, __author__, __email__

with open('README.md') as fh:
    long_description = fh.read()

setuptools.setup(
    name=__name__,
    version=__version__,
    description=__desc__,
    author=__author__,
    author_email=__email__,
    url='https://github.com/chapinb/libvxshare',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=setuptools.find_packages(),
    install_requires=[
        "requests ~= 2.24.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3 :: Only",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "Natural Language :: English",
        "Topic :: Scientific/Engineering :: Information Analysis",
        "Topic :: Security",
        "Topic :: Utilities"
    ]
)
