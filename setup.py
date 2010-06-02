#!/usr/bin/env python

from distutils.core import setup

# to run unit tests, do this:
#  python jpake/test/test_jpake.py

setup(name="jpake",
      version="0.0a0",
      description="J-PAKE password-authenticated key exchange (pure python)",
      author="Brian Warner",
      author_email="warner-pyjpake@lothar.com",
      url="http://github.com/warner/python-jpake",
      packages=["jpake"],
      license="MIT",
      )
