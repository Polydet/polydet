from setuptools import find_packages, setup

setup(name='polydet',
      version='0.2',
      description='Detect suspicious data in files',
      author='Julien Campion, Hugo Laloge',
      author_email='jlc72@kent.ac.uk, hljl2@kent.ac.uk',
      url='https://git.cs.kent.ac.uk/hljl2/polyglot-detector',
      packages=find_packages(exclude=['tests']),
      zip_safe=True,
      install_requires=['pefile', 'file-magic', 'yara-python'])
