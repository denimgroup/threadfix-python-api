#!/usr/bin/env python

import os
import sys

from ThreadFixPythonApi import __version__ as version

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

with open('README.rst', 'r') as f:
    readme = f.read()

# Publish helper
if sys.argv[-1] == 'build':
    os.system('python setup.py sdist bdist_wheel')
    sys.exit(0)

if sys.argv[-1] == 'install':
    os.system('python setup.py sdist --formats=zip')
    sys.exit(0)
    
setup(
    name='threadfixproapi',
    packages=['ThreadFixPythonApi', '_utils',],
    version=version,
    description='Python library enumerating the ThreadFix Professional RESTFul API.',
    long_description='A python implementation of ThreadFix\'s API for easier use with python. Built off of original work by (c) 2018 Target Brands, Inc.',
    author='Dan Cornell',
    author_email='dancornell@gmail.com',
    url='https://github.com/denimgroup/threadfix-python-api',
    download_url='https://github.com/denimgroup/threadfix-python-api/tarball/' + version,
    license='MIT',
    zip_safe=True,
    install_requires=['requests'],
    keywords=['threadfix', 'api', 'security', 'software', 'denim group', 'sast', 'dast'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Topic :: Software Development',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.0',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ]
)
