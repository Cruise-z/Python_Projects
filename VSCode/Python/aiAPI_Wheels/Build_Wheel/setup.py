from setuptools import setup, find_packages
import os
print(os.getcwd())  # 打印当前工作目录

setup(name='aiAPI', # 库的名称
      version='1.0',    # 版本号
      description='Some packaging interface functions of AI Models API',
      author='Cruise.zrz',
      author_email='cruise.zrz@gmail.com',
      packages=find_packages(),  # 自动找到 `your_package/`
      install_requires=[
          'openai>=1.33.0', 
          'transformers>=4.0,<5.0', 
          'nltk>=3.8',
          'torch>=2.3.1',
          'torchaudio>=2.3.1',
          'torchvision>=0.18.1'
          ],
      python_requires='>=3.7',
      long_description=open("README.md").read(),long_description_content_type="text/markdown",
      url="https://github.com/Cruise-z/AI_API-Wheel"
)