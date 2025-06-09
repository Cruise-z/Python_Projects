class UnsignedInt32:
    def __init__(self, value=0):
        # 初始化时确保值为 32 位无符号整数
        self.value = value & 0xFFFFFFFF  # 保证值在 32 位无符号整数范围内

    def __repr__(self):
        return f"UnsignedInt32({self.value})"

    def __int__(self):
        return self.value

    # 加法
    def __add__(self, other):
        if isinstance(other, UnsignedInt32):
            other = other.value
        result = (self.value + other) & 0xFFFFFFFF  # 确保结果是 32 位
        return UnsignedInt32(result)

    # 减法
    def __sub__(self, other):
        if isinstance(other, UnsignedInt32):
            other = other.value
        result = (self.value - other) & 0xFFFFFFFF  # 确保结果是 32 位
        return UnsignedInt32(result)

    # 按位与
    def __and__(self, other):
        if isinstance(other, UnsignedInt32):
            other = other.value
        result = self.value & other
        return UnsignedInt32(result)

    # 按位或
    def __or__(self, other):
        if isinstance(other, UnsignedInt32):
            other = other.value
        result = self.value | other
        return UnsignedInt32(result)

    # 按位异或
    def __xor__(self, other):
        if isinstance(other, UnsignedInt32):
            other = other.value
        result = self.value ^ other
        return UnsignedInt32(result)

    # 左移
    def __lshift__(self, other):
        result = (self.value << other) & 0xFFFFFFFF  # 确保结果是 32 位
        return UnsignedInt32(result)

    # 右移
    def __rshift__(self, other):
        result = self.value >> other
        return UnsignedInt32(result)

    # 比较
    def __eq__(self, other):
        if isinstance(other, UnsignedInt32):
            return self.value == other.value
        return self.value == other

    def __lt__(self, other):
        if isinstance(other, UnsignedInt32):
            return self.value < other.value
        return self.value < other

    def __le__(self, other):
        if isinstance(other, UnsignedInt32):
            return self.value <= other.value
        return self.value <= other

    def __gt__(self, other):
        if isinstance(other, UnsignedInt32):
            return self.value > other.value
        return self.value > other

    def __ge__(self, other):
        if isinstance(other, UnsignedInt32):
            return self.value >= other.value
        return self.value >= other


# 示例使用
a = UnsignedInt32(0xFFFFFFFF)  # 最大值 32 位无符号整数
b = UnsignedInt32(10)

# 加法
print(a + b)  # UnsignedInt32(9)

# 减法
print(a - b)  # UnsignedInt32(4294967285)

# 按位与
print(a & b)  # UnsignedInt32(10)

# 按位或
print(a | b)  # UnsignedInt32(4294967305)

# 按位异或
print(a ^ b)  # UnsignedInt32(4294967295)

# 左移
print(a << 2)  # UnsignedInt32(4294967292)

# 右移
print(a >> 2)  # UnsignedInt32(1073741823)
