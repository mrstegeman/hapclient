from distutils.core import setup

setup(
    name='hapclient',
    packages=['hapclient', 'hapclient.http_parser', 'hapclient.model'],
    version='0.5',
    description='Library to implement a HAP (HomeKit) controller',
    author='Michael Stegeman',
    author_email='mrstegeman@gmail.com',
    url='https://github.com/mrstegeman/hapclient',
    keywords=['HomeKit', 'HAP'],
    classifiers=[],
    install_requires=[
        'hkdf',
        'pynacl',
        'zeroconf',
    ],
)
