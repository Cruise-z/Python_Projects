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
  
  The next version will update the `chatgpt` related file upload logic based on the `kimi AI` file upload logic.