Some packaging interface functions of AI Models API

Steps to Build this Wheel：
- Enter folder: ./Build_Wheel
- Run command: python -m build

FIX:
- version 1.0: 
  Init.
- version 1.0.1: 
  Fix the issue where the stream mode chunk is empty.
- version 1.0.2:
  - Optimize file upload dialogue logic, control whether files enter cache through cache tags.
  - Add common chat conversation reference caching logic.
  
  The next version will update the `gpt` related file upload logic based on the `kimi AI` file upload logic.
- version 1.0.3:
  - `gpt` related file upload logic init
  
  At present, there is no clear file caching and uploading mechanism related to GPT, and this issue may be resolved in the future