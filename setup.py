from distutils.core import setup

with open('requirements.txt') as f:
    requires = f.read().splitlines()

setup(
    name='ibm-security-notebooks',
    version='0.0.1',
    author='Raymund Lin',
    author_email='raymundl@tw.ibm.com',
    packages=['pyclient'],
    scripts=[],
    url='https://github.com/ibm/ibm-security-notebooks',
    license="Apache License 2.0",
    description='A python module for interacting with APIs of IBM Security products.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    install_requires=requires,
)
