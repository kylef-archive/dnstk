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
    install_requires=['zokket >= 1.2'],
    url='https://github.com/kylef/dnstk/',
    download_url='http://github.com/kylef/dnstk/zipball/{}'.format(dnstk.__version__),
    license='BSD'
)

