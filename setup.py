
# -*- coding: utf-8 -*-

# DO NOT EDIT THIS FILE!
# This file has been autogenerated by dephell <3
# https://github.com/dephell/dephell

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


import os.path

readme = ''
here = os.path.abspath(os.path.dirname(__file__))
readme_path = os.path.join(here, 'README.rst')
if os.path.exists(readme_path):
    with open(readme_path, 'rb') as stream:
        readme = stream.read().decode('utf8')


setup(
    long_description=readme,
    name='qctrl-jupyterhub-authenticator',
    version='0.0.12',
    description='Q-CTRL JupyterHub JWT Authenticator',
    python_requires='>=3.6.4',
    author='Q-CTRL',
    author_email='support@q-ctrl.com',
    packages=['jwtauthenticator'],
    package_dir={"": "."},
    package_data={},
    install_requires=['jupyterhub>=1.0.0', 'pyjwt==2.*,>=2.0.1'],
    extras_require={"dev": ["pylama==7.*,>=7.7.1"]},
    entry_points={
        'jupyterhub.authenticators': [
            'jwt = jwtauthenticator.jwtauthenticator:JSONWebTokenAuthenticator'
        ]
    }
)
