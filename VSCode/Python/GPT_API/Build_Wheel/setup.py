from setuptools import setup

setup(name='AI_API', # 库的名称
      version='1.2',    # 版本号
      description='Some packaging interface functions of GPT API',
      author='Cruise.zrz',
      author_email='cruise.zrz@gmail.com',
      py_modules=['aiAPI'], # 需要导入使用该模块时
      install_requires=[
          'openai>=1.33.0', 
          'transformers>=4.0,<5.0', 
          'nltk>=3.8',
          'torch>=2.3.1',
          'torchaudio>=2.3.1',
          'torchvision>=0.18.1'
          ],
      python_requires='>=3.7',
)