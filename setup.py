import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

__sdesc = 'Python module to parse CPE trees from NVD vulnerabilities'

setup(name             = 'python-cpe-parser',
      description      = __sdesc,
      long_description = read('README.md'),
      py_modules       = ['cpeparser'],
      version          = '1.0',
      author           = 'David Ford',
      author_email     = 'david@blue-labs.org',
      maintainer       = 'David Ford',
      maintainer_email = 'david@blue-labs.org',
      url              = 'https://github.com/FirefighterBlu3/python-cpe-parser',
      download_url     = 'https://github.com/FirefighterBlu3/python-cpe-parser',
      bugtrack_url     = 'https://github.com/FirefighterBlu3/python-cpe-parser/issues',
      license          = 'License :: OSI Approved :: Apache Software License',
      platforms        = ['i686','x86_64'],
      classifiers      = [
          'Development Status :: 4 - Beta',
          'Environment :: Other Environment',
          'Intended Audience :: Developers',
          'Intended Audience :: Information Technology',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: Apache Software License',
          'Operating System :: POSIX',
          'Operating System :: POSIX :: Linux',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 3',
          'Topic :: Database',
          'Topic :: Internet :: WWW/HTTP :: Indexing/Search',
          'Topic :: Security',
          ],
      )
