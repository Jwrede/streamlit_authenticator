from setuptools import setup


setup(
    name="streamlit_authenticator",
    version="1.0",
    packages=['streamlit_authenticator'],
    include_package_data=True,
    install_requires = [
        'cognitojwt==1.4.1',
        'streamlit',
        'cryptography==38.0.4',
        'requests'
    ]
)