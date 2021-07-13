import os
import sys

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

# read in the contents of the README file
from os import path
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

# Publish helper
if sys.argv[-1] == 'build':
    os.system('python setup.py sdist bdist_wheel')
    sys.exit(0)

if sys.argv[-1] == 'install':
    os.system('python setup.py sdist --formats=zip')
    sys.exit(0)

version = '1.0.12'

setup(
    name='ThreadFixProAPI',
    packages=['ThreadFixProAPI', 'ThreadFixProAPI.Applications', 'ThreadFixProAPI.Applications._utils', 'ThreadFixProAPI.Networks', 'ThreadFixProAPI.Networks._utils'],
    version=version,
    description='Python library enumerating the ThreadFix Professional RESTFul API.',
    long_description=long_description,
    long_description_content_type='text/x-rst',
    author='Dan Cornell',
    author_email='dancornell@gmail.com',
    url='https://github.com/denimgroup/threadfix-python-api',
    download_url='https://github.com/denimgroup/threadfix-python-api/tarball/' + version,
    license='MIT',
    zip_safe=True,
    install_requires=['requests', 'urllib3'],
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

