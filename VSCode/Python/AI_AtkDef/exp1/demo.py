import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
from torchvision import datasets, transforms
from torchsummary import summary
from torch.utils.data import DataLoader
import matplotlib.pyplot as plt

# 设置设备为GPU或CPU
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# 数据集加载函数
def load_dataset(dataset_name):
    if dataset_name == 'MNIST':
        transform = transforms.Compose([
            transforms.ToTensor(),
            transforms.Normalize((0.1307,), (0.3081,))
        ])
        train_dataset = datasets.MNIST('./exp1/data', train=True, download=True, transform=transform)
        test_dataset = datasets.MNIST('./exp1/data', train=False, transform=transform)
    elif dataset_name == 'CIFAR10':
        transform = transforms.Compose([
            transforms.ToTensor(),
            transforms.Normalize((0.5, 0.5, 0.5), (0.5, 0.5, 0.5))
        ])
        train_dataset = datasets.CIFAR10('./exp1/data', train=True, download=True, transform=transform)
        test_dataset = datasets.CIFAR10('./exp1/data', train=False, transform=transform)
    elif dataset_name == 'GTSRB':
        # GTSRB数据集的transform可以自定义
        transform = transforms.Compose([
            transforms.Resize((32, 32)),
            transforms.ToTensor(),
            transforms.Normalize((0.5,), (0.5,))
        ])
        # 假设已经下载并解压缩GTSRB数据集
        train_dataset = datasets.ImageFolder('./exp1/data/GTSRB/Train', transform=transform)
        test_dataset = datasets.ImageFolder('./exp1/data/GTSRB/Test', transform=transform)
    else:
        raise ValueError('Unknown dataset')

    train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=1, shuffle=True)
    return train_loader, test_loader

# 定义CNN模型
class CNN(nn.Module):
    def __init__(self, input_channels):
        super(CNN, self).__init__()
        self.conv1 = nn.Conv2d(input_channels, 64, 3, 1)
        self.bn1 = nn.BatchNorm2d(64)
        self.conv2 = nn.Conv2d(64, 128, 3, 1)
        self.bn2 = nn.BatchNorm2d(128)
        self.conv3 = nn.Conv2d(128, 256, 3, 1)
        self.bn3 = nn.BatchNorm2d(256)
        self.dropout = nn.Dropout(0.5)

        # 全连接层的输入尺寸将由forward函数动态确定
        self.fc1 = None
        self.fc2 = nn.Linear(256, 10)

    def forward(self, x):
        x = F.relu(self.bn1(self.conv1(x)))
        x = F.relu(self.bn2(self.conv2(x)))
        x = F.relu(self.bn3(self.conv3(x)))
        x = F.max_pool2d(x, 2)
        x = torch.flatten(x, 1)
        
        # 动态确定全连接层的输入尺寸
        if self.fc1 is None:
            self.fc1 = nn.Linear(x.shape[1], 256).to(x.device)
        
        x = self.dropout(F.relu(self.fc1(x)))
        x = self.fc2(x)
        return x

# 训练和测试函数
def train(model, device, train_loader, optimizer, epoch):
    model.train()
    for batch_idx, (data, target) in enumerate(train_loader):
        data, target = data.to(device), target.to(device)
        optimizer.zero_grad()
        output = model(data)
        loss = F.cross_entropy(output, target)
        loss.backward()
        optimizer.step()
        if batch_idx % 100 == 0:
            print(f'Train Epoch: {epoch} [{batch_idx * len(data)}/{len(train_loader.dataset)}]'
                  f'\tLoss: {loss.item():.6f}')

def test(model, device, test_loader):
    model.eval()
    test_loss = 0
    correct = 0
    with torch.no_grad():
        for data, target in test_loader:
            data, target = data.to(device), target.to(device)
            output = model(data)
            test_loss += F.cross_entropy(output, target, reduction='sum').item()
            pred = output.argmax(dim=1, keepdim=True)
            correct += pred.eq(target.view_as(pred)).sum().item()

    test_loss /= len(test_loader.dataset)
    accuracy = 100. * correct / len(test_loader.dataset)
    print(f'\nTest set: Average loss: {test_loss:.4f}, '
          f'Accuracy: {correct}/{len(test_loader.dataset)} ({accuracy:.0f}%)\n')

# FGSM方法实现对抗攻击
def fgsm_attack(data, epsilon, data_grad, targeted=False):
    if targeted:
        perturbed_data = data - epsilon * data_grad.sign()
    else:
        perturbed_data = data + epsilon * data_grad.sign()
    return perturbed_data

# 损失函数生成，包含目标攻击非目标攻击两个选项
def attack_image(model, device, data, target, epsilon, targeted=False, target_label=None):
    data, target = data.to(device), target.to(device)
    data.requires_grad = True
    output = model(data)
    
    if targeted:
        loss = F.cross_entropy(output, target_label)
    else:
        loss = F.cross_entropy(output, target)

    model.zero_grad()
    loss.backward()
    data_grad = data.grad.data
    
    perturbed_data = fgsm_attack(data, epsilon, data_grad, targeted)
    
    return perturbed_data

# 显示图片
def imshow(img, title):
    img = img.detach().cpu().numpy().squeeze()
    if len(img.shape) == 2:
        # MNIST数据集中的灰度图像
        plt.imshow(img, cmap="gray")
    else:  
        # CIFAR10数据集中的彩色图像
        img = img.transpose(1, 2, 0)  # 转换为 (height, width, channels)
        # 数据集在加载时进行了标准化，在这里进行反标准化
        img = img * 0.5 + 0.5  # 这将把图像像素值恢复到[0, 1]的范围
        plt.imshow(img)
    plt.title(title)
    plt.show()

# 攻击主程序
def attack(dataset_name:str, input_number:int, target_number:int, epsilon:int):
    train_loader, test_loader = load_dataset(dataset_name)

    if dataset_name == 'MNIST':
        # MNIST数据集使用单通道
        input_channels = 1
    else:
        input_channels = 3

    model = CNN(input_channels).to(device)
    
    # 获得一个数据集中的样本得到模型的输入大小，进而使用summary库得到该模型的详细参数
    data_iter = iter(train_loader)
    images, labels = next(data_iter)
    summary(model=model, input_size=images.shape[1:])
    
    optimizer = optim.Adam(model.parameters(), lr=0.001)

    # 训练轮数为6轮
    for epoch in range(1, 6):
        train(model, device, train_loader, optimizer, epoch)
        test(model, device, test_loader)

    # 从测试集中选择指定数字的样本
    original_data = None
    original_label = None
    for data, target in test_loader:
        if target.item() == input_number:
            original_data = data
            original_label = target
            imshow(original_data, f"Original Image - {input_number}")
            break

    if original_data is None:
        print(f"No image of {input_number} found in the dataset.")
        return

    # none target attack
    perturbed_data = attack_image(
        model, device, original_data, original_label, epsilon, targeted=False
    )
    output = model(perturbed_data)
    final_pred = output.argmax(dim=1, keepdim=True)
    print(f'Original Label: {input_number}, Predicted after Untargeted Attack: {final_pred.item()}')
    imshow(perturbed_data, f"Perturbed Image (Untargeted Attack) - Predicted: {final_pred.item()}")

    # target attack
    if target_number is not None:
        target_label = torch.tensor([target_number]).to(device)
        perturbed_data_targeted = attack_image(
            model, device, original_data, original_label, epsilon, targeted=True, target_label=target_label
        )
        output = model(perturbed_data_targeted)
        final_pred_targeted = output.argmax(dim=1, keepdim=True)
        print(f'Original Label: {input_number}, Predicted after Targeted Attack (Target: {target_number}): {final_pred_targeted.item()}')
        imshow(
            perturbed_data_targeted,
            f"Perturbed Image (Targeted Attack) - Predicted: {final_pred_targeted.item()}"
        )

# 进行攻击
attack(dataset_name='MNIST', input_number=4, target_number=8, epsilon=0.5)
