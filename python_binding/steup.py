# setup.py

from setuptools import setup, Extension

setup(
    name='quantum_resistant',
    version='0.1',
    ext_modules=[Extension('quantum_resistant', ['quantum_resistant.c'])],
)
