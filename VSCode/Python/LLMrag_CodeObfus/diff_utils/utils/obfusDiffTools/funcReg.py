# 注册表
funcRegister = {}

# 装饰器
def register(tag):
    def decorator(func):
        funcRegister[tag] = func
        return func
    return decorator

def tagFunc(tag:str, *args, **kwargs):
    func = funcRegister.get(tag)
    if func:
        return func(*args, **kwargs)
    else:
        print(f"Function for tag {tag} not found.")
        return None