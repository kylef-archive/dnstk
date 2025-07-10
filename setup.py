from setuptools import setup
import dnstk

setup(
    name='dnstk',
    version=dnstk.__version__,
    author='Kyle Fuller',
    author_email='inbox@kylefuller.co.uk',
    packages=['dnstk'],
    entry_points={
        'console_scripts': [
            'dnstk-cli = dnstk.client:main',
        ]
    },
    url='https://github.com/kylef/dnstk/',
    license='BSD',
    description='Python DNS toolkit',
    long_description=open('README.rst').read(),
    classifiers = [
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.4',
        'Topic :: Internet :: Name Service (DNS)',
        'Topic :: Software Development :: Libraries',
    ]
)

