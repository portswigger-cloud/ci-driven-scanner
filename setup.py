#  burp_wrapper
#  ---------------
#  A wrapper for the BurpSuite CI Scanning conatiner to provide
#  interesting and useful outputs.
#
#  Author:  Tim Birkett <tim.birkettdev@portswigger.net>
#  Website: https://github.com/portswigger-cloud/ci-driven-scanner
#  License: MIT License (see LICENSE file)

import codecs

from setuptools import setup

dependencies = [
    "art==6.0",
    "Jinja2==3.1.2",
    "junitparser==3.1.0",
    "lxml==4.9.3",
]

setup(
    name="burp_wrapper",
    version="0.0.0",
    url="https://github.com/portswigger-cloud/ci-driven-scanner",
    license="MIT",
    author="Tim Birkett",
    author_email="tim.birkett@portswigger.net",
    description="A wrapper for the BurpSuite CI Scanning conatiner to provide interesting and useful outputs.",
    packages=["burp_wrapper"],
    include_package_data=True,
    zip_safe=False,
    platforms="any",
    install_requires=dependencies,
    entry_points={
        "console_scripts": [
            "burp_wrapper = burp_wrapper.main:cli",
        ],
    },
    classifiers=[
        # As from http://pypi.python.org/pypi?%3Aaction=list_classifiers
        "Development Status :: 4 - Beta",
        "Topic :: Utilities",
        "Topic :: System :: Monitoring",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3 :: Only",
    ],
)
