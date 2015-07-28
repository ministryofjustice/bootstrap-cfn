#!/usr/bin/env python

from setuptools import find_packages, setup

setup(
    name='bootstrap_cfn',
    version='0.5.5',
    url='http://github.com/ministryofjustice/bootstrap_cfn/',
    license='LICENSE',
    author='MOJDS',
    author_email='tools@digital.justice.gov.uk',
    description='MOJDS cloudformation bootstrap tool',
    long_description="",
    packages=find_packages(exclude=["tests"]),
    package_data={'bootstrap_cfn': ['stacks/*']},
    zip_safe=False,
    platforms='any',
    test_suite='tests',
    install_requires=[
        'Fabric>=1.10.1',
        'PyYAML>=3.11',
        'boto>=2.36.0',
        'troposphere>=1.0.0',
    ],
    setup_requires=[
        'mock>=1.0.1',
        'testfixtures>=4.1.2',
        'nose',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
)
