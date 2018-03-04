#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This Source Code Form is subject to the terms of the
# Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
# with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'LICENSE.txt'), encoding='utf-8') as f:
    license = f.read()
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='wiregr',
    version='0.1.0',

    description='Wireshark Dissector Regression Utils',
    long_description=long_description,

    url='https://github.com/anticodeninja/wiregr',

    maintainer='anticodeninja',
    author='anticodeninja',

    license=license,

    packages=find_packages(),
    install_requires = ['pyyaml'],

    entry_points={
        'console_scripts': [
            'wiregr=wiregr:main',
        ],
    },
)

