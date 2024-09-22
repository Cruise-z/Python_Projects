import cv2
import os
import numpy as np
import random
import tensorflow as tf
from tensorflow.keras import layers, models
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.datasets import mnist

# 定义标准的 z 和 r 形状为 5x5 模板
z_shape = np.array([
    [1, 1, 1, 1, 1],  # 顶部横线
    [0, 0, 0, 0, 1],  # 斜线
    [0, 0, 0, 1, 0],
    [0, 0, 1, 0, 0],
    [1, 1, 1, 1, 1]   # 底部横线
], dtype=np.float32)

r_shape = np.array([
    [1, 1, 1, 1, 0],  # 顶部横线
    [1, 0, 0, 0, 1],  # 左侧竖线和顶部右侧竖线
    [1, 1, 1, 1, 0],  # 中间横线
    [1, 0, 0, 1, 0],  # 右下角竖线
    [1, 0, 0, 0, 1]   # 右下角竖线
], dtype=np.float32)

# 定义将trigger附加在图像上，并修改label为攻击目标的函数
def attach_trigger(batch_images, batch_labels, mask, trigger, target, ratio):
    batch_size = len(batch_images)
    trigger_num = int(round(batch_size * ratio))
    
    batch_images[0:trigger_num] = batch_images[0:trigger_num] * (1 - mask) + trigger * mask
    batch_labels[0:trigger_num] = 0
    batch_labels[0:trigger_num, target] = 1
    
    state = np.random.get_state()
    np.random.shuffle(batch_images)
    np.random.set_state(state)
    np.random.shuffle(batch_labels)
    
    return batch_images, batch_labels

#权重初始化
def weight_variable(shape):
    initial = tf.random.truncated_normal(shape, stddev=0.1)
    return tf.Variable(initial, name="weight")

def bias_variable(shape):
    initial = tf.constant(0.1, shape=shape)
    return tf.Variable(initial, name="bias")

#卷积和池化函数
def conv2d(x, W):
    return tf.nn.conv2d(x, W, strides=[1, 1, 1, 1], padding='SAME')

def max_pooling_2x2(x):
    return tf.nn.max_pool2d(x, ksize=[1, 2, 2, 1], strides=[1, 2, 2, 1], padding='SAME')

# 定义模型结构
def define_model():
    model = models.Sequential()
    model.add(layers.Conv2D(32, (3, 3), activation='relu', input_shape=(28, 28, 1)))
    model.add(layers.Conv2D(32, (3, 3), activation='relu'))
    model.add(layers.MaxPooling2D((2, 2)))
    
    model.add(layers.Conv2D(64, (3, 3), activation='relu'))
    model.add(layers.Conv2D(64, (3, 3), activation='relu'))
    model.add(layers.MaxPooling2D((2, 2)))
    
    model.add(layers.Flatten())
    model.add(layers.Dense(512, activation='relu'))
    model.add(layers.Dropout(0.5))
    model.add(layers.Dense(10, activation='softmax'))
    
    model.compile(optimizer=Adam(1e-4), loss='categorical_crossentropy', metrics=['accuracy'])
    return model

# 创建触发器图像函数
def create_trigger_image(trigger_shapes, positions):
    """
    根据指定的位置将 trigger_shapes 的图案嵌入到 28x28 大小的图像中。
    trigger_shapes: 字母的形状（z_shape 或 r_shape）
    positions: 字母在图像中的位置（左上角坐标 (row, col)）
    """
    trigger_image = np.zeros((28, 28), dtype=np.float32)  # 创建二维触发器图像
    for shape, pos in zip(trigger_shapes, positions):
        row, col = pos
        # 检查是否越界，避免插入的位置超出图像范围
        if row + shape.shape[0] <= 28 and col + shape.shape[1] <= 28:
            trigger_image[row:row+5, col:col+5] = shape  # 嵌入二维触发器
    return trigger_image

def train_backdoor_model(modelname, target, trigger, mask, ratio):
    (train_images, train_labels), (test_images, test_labels) = mnist.load_data()
    
    # 数据预处理
    train_images = train_images.reshape((-1, 28, 28, 1)).astype('float32') / 255
    test_images = test_images.reshape((-1, 28, 28, 1)).astype('float32') / 255

    train_labels = tf.keras.utils.to_categorical(train_labels, 10)
    test_labels = tf.keras.utils.to_categorical(test_labels, 10)

    # 加载模型
    model = define_model()

    # 训练模型
    for i in range(2001):
        idx = np.random.choice(len(train_images), 100, replace=False)
        batch_images = train_images[idx]
        batch_labels = train_labels[idx]
        
        # 添加 trigger
        batch_images, batch_labels = attach_trigger(batch_images, batch_labels, mask, trigger, target, ratio)
        
        if i % 100 == 0:
            loss, acc = model.evaluate(batch_images, batch_labels, verbose=0)
            print(f"step {i}, training accuracy {acc}")

        model.train_on_batch(batch_images, batch_labels)

    # 测试干净数据准确率
    clean_loss, clean_acc = model.evaluate(test_images, test_labels, verbose=0)
    print(f"Clean data accuracy: {clean_acc}")

    # 测试带 trigger 数据攻击成功率
    test_images, test_labels = attach_trigger(test_images, test_labels, mask, trigger, target, ratio=1)
    backdoor_loss, backdoor_acc = model.evaluate(test_images, test_labels, verbose=0)
    print(f"Backdoor attack success rate: {backdoor_acc}")

    # 保存模型
    if not os.path.exists("./exp3/model/"):
        os.makedirs("./exp3/model/")
    model.save(f"./exp3/model/{modelname}.keras")

#攻击目标类别
target = 0

# 生成触发器图案
trigger = create_trigger_image([z_shape, r_shape, z_shape], [(22, 21), (22, 27), (22, 32)])
# 扩展 trigger 为 3D 符合图像形状
trigger = np.expand_dims(trigger, axis=-1)

# mask控制trigger位置
mask = np.zeros((28, 28, 1), dtype=np.float32)
mask[22:27, 21:26, :] = 1  # 第一个 "z"
mask[22:27, 27:32, :] = 1  # "r"
mask[22:27, 32:37, :] = 1  # 第二个 "z"

# 数据集污染比例
ratio = 0.1
modelname = 'zrz_backdoor'
train_backdoor_model(modelname, target, trigger, mask, ratio)
