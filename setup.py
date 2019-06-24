from distutils.core import setup

setup(
    name='ThreadFixPythonAPI',
    version='1.0.6',
    packages=['ThreadFixPythonApi', '_utils',],
    license='MIT',
    long_description='A python implementation of ThreadFix\'s API for easier use with python. Built off of original work by (c) 2018 Target Brands, Inc.',
    install_requires=['requests>=2.22.0', 'urllib3>=1.25.3']
)