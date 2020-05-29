from setuptools import setup

DEPENDENCIES = open('requirements.txt', 'r').read().split('\n')
README = open('README.md', 'r').read()

setup(
    name='immuniwebsearch',
    version='1.0.0',
    description='Python library and CLI scraper for ImmuniWeb Radar (https://www.immuniweb.com/radar/)',
    long_description=README,
    long_description_content_type='text/markdown',
    author='Robert Paul',
    author_email='robert.paul24@t-mobile.com',
    url="http://github.com/BraveLittleRoaster/",
    packages=['immuniwebsearch'],
    entry_points={'console_scripts': ['immuniwebsearch=immuniwebsearch.main:main']},
    install_requires=DEPENDENCIES,
    keywords=['security', 'network', 'threat intel'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)