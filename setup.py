from distutils.core import setup

setup(name='pydig',
      version='1.3.0',
      scripts=['pydig'],
      description='DNS query tool',
      author='Shumon Huque',
      author_email='shuque@gmail.com',
      url='https://github.com/shuque/pydig',
      packages=['pydiglib'],
      long_description = \
      """pydig - a DNS query tool in Python.""",
      )
