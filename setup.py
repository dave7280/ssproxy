import codecs
from setuptools import setup


with codecs.open('README.md', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="ssproxy",
    version="0.0.1",
    license='http://www.apache.org/licenses/LICENSE-2.0',
    description="A super simple proxy",
    author='liangsijian',
    author_email='liangsijian@foxmail.com',
    url='https://github.com/liangsijian/ssproxy',
    packages=['ssproxy',],
    install_requires=['tornado'],
    entry_points="""
    [console_scripts]
    ssproxy = ssproxy.ssproxy:main
    """,
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Internet :: Proxy Servers',
    ],
    long_description=long_description,
)
