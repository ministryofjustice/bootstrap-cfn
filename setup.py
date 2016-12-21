#!/usr/bin/env python

from setuptools import find_packages, setup

setup(
    name='bootstrap_cfn',
    version='1.3.0rc1',
    url='http://github.com/ministryofjustice/bootstrap_cfn/',
    license='LICENSE',
    author='MOJDS',
    author_email='tools@digital.justice.gov.uk',
    description='MOJDS cloudformation bootstrap tool',
    long_description="",
    packages=find_packages(exclude=["tests"]),
    include_package_data=True,
    package_data={'bootstrap_cfn': ['config_defaults.yaml', 'stacks/*']},
    zip_safe=False,
    platforms='any',
    test_suite='tests',
    install_requires=[
        'Fabric>=1.10.1',
        'PyYAML>=3.11',
        'boto>=2.36.0',
        'boto3>=1.2.2',
        'dnspython>=1.12.0',
        'netaddr>=0.7.18',
        'troposphere>=1.0.0',
    ],
    setup_requires=[
        'mock>=1.0.1',
        'testfixtures>=4.1.2',
        'nose',
    ],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
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
