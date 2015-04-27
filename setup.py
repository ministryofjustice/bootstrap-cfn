#!/usr/bin/env python

"""
bootstrap_cfn
-----

bootstrap_cfn is MOJ Digital Services Cloudformation stack

Setup
`````````````````

And run it:

.. code:: bash

    $ pip install -r requirements.txt

Links
`````

* `documentation <http://github.com/ministryofjustice/bootstrap-cfn/docs>`_
* `development version
  <http://github.com/ministryofjustice/bootstrap-cfn>`_

"""
from setuptools import setup, find_packages

setup(
    name='bootstrap_cfn',
    version='0.3.1',
    url='http://github.com/ministryofjustice/bootstrap_cfn/',
    license='LICENSE',
    author='MOJDS',
    author_email='tools@digital.justice.gov.uk',
    description='MOJDS cloudformation bootstrap tool',
    long_description=__doc__,
    packages=find_packages(),
    package_data={'bootstrap_cfn': ['stacks/*']},
    zip_safe=False,
    platforms='any',
    test_suite='tests',
    install_requires=[
        'Fabric>=1.10.1',
        'PyYAML>=3.11',
        'boto>=2.36.0',
        'mock>=1.0.1',
        'testfixtures>=4.1.2',
    ],
    classifiers=[
        'Development Status :: 1 - Alpha',
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
