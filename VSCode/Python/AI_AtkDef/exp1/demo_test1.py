import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
from torchvision import datasets, transforms
from torch.utils.data import DataLoader
import os

os.environ['http_proxy'] = 'http://127.0.0.1:7897'
os.environ['https_proxy'] = 'http://127.0.0.1:7897'

# 设置设备为GPU或CPU
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(device)

# 数据集加载（MNIST）
transform = transforms.Compose([transforms.ToTensor(), transforms.Normalize((0.1307,), (0.3081,))])
train_dataset = datasets.MNIST('./data', train=True, download=True, transform=transform)
test_dataset = datasets.MNIST('./data', train=False, transform=transform)
train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)
test_loader = DataLoader(test_dataset, batch_size=64, shuffle=False)

# 定义一个简单的CNN模型
class CNN(nn.Module):
    def __init__(self):
        super(CNN, self).__init__()
        self.conv1 = nn.Conv2d(1, 32, 3, 1)
        self.conv2 = nn.Conv2d(32, 64, 3, 1)
        self.fc1 = nn.Linear(9216, 128)
        self.fc2 = nn.Linear(128, 10)

    def forward(self, x):
        x = F.relu(self.conv1(x))
        x = F.relu(self.conv2(x))
        x = F.max_pool2d(x, 2)
        x = torch.flatten(x, 1)
        x = F.relu(self.fc1(x))
        x = self.fc2(x)
        return x

# 模型实例化
model = CNN().to(device)
optimizer = optim.Adam(model.parameters(), lr=0.001)

# 训练模型
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
            print(f'Train Epoch: {epoch} [{batch_idx * len(data)}/{len(train_loader.dataset)}]\tLoss: {loss.item():.6f}')

# 测试模型
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
    print(f'\nTest set: Average loss: {test_loss:.4f}, Accuracy: {correct}/{len(test_loader.dataset)} ({accuracy:.0f}%)\n')

# 训练和测试
for epoch in range(1, 4):
    train(model, device, train_loader, optimizer, epoch)
    test(model, device, test_loader)

# 对抗攻击实现（FGSM方法）
def fgsm_attack(model, device, data, target, epsilon, targeted=False, target_label=None):
    data, target = data.to(device), target.to(device)
    data.requires_grad = True
    output = model(data)

    if targeted:
        # 确保 target_label 与数据批次大小匹配
        target_label = target_label.to(device)
        loss = F.cross_entropy(output, target_label)
    else:
        loss = F.cross_entropy(output, target)

    model.zero_grad()
    loss.backward()
    data_grad = data.grad.data

    # 生成扰动
    if targeted:
        perturbed_data = data - epsilon * data_grad.sign()
    else:
        perturbed_data = data + epsilon * data_grad.sign()

    perturbed_data = torch.clamp(perturbed_data, 0, 1)
    return perturbed_data


# 对抗攻击实验
def test_attack(model, device, test_loader, epsilon, targeted=False, target_label=None):
    correct = 0
    for data, target in test_loader:
        data, target = data.to(device), target.to(device)

        # 生成对抗样本
        if targeted:
            # 确保 target_label 的大小与当前批次大小一致
            batch_size = data.size(0)
            target_label = target_label[:batch_size] if len(target_label) > batch_size else target_label
            perturbed_data = fgsm_attack(model, device, data, target, epsilon, targeted=True, target_label=target_label)
        else:
            perturbed_data = fgsm_attack(model, device, data, target, epsilon, targeted=False)

        # 使用对抗样本进行预测
        output = model(perturbed_data)
        final_pred = output.argmax(dim=1, keepdim=True)

        if targeted:
            correct += final_pred.eq(target_label.view_as(final_pred)).sum().item()
        else:
            correct += final_pred.ne(target.view_as(final_pred)).sum().item()

    accuracy = 100. * correct / len(test_loader.dataset)
    print(f'Epsilon: {epsilon}\tTest Accuracy = {accuracy:.2f}%')
    return accuracy


# 测试非目标攻击
test_attack(model, device, test_loader, epsilon=0.01, targeted=False)

# 测试目标攻击
target_label = torch.tensor([1] * 64).to(device)  # 假设目标类别为1
test_attack(model, device, test_loader, epsilon=0.01, targeted=True, target_label=target_label)
