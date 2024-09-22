import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
from torchvision import datasets, transforms
from torch.utils.data import DataLoader
import matplotlib.pyplot as plt

# 设置设备为GPU或CPU
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# 数据集加载（MNIST）
transform = transforms.Compose([
    transforms.ToTensor(),
    transforms.Normalize((0.1307,), (0.3081,))
])
train_dataset = datasets.MNIST('./data', train=True, download=True, transform=transform)
test_dataset = datasets.MNIST('./data', train=False, transform=transform)
train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)
test_loader = DataLoader(test_dataset, batch_size=1, shuffle=True)

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
            print(f'Train Epoch: {epoch} [{batch_idx * len(data)}/{len(train_loader.dataset)}]'
                  f'\tLoss: {loss.item():.6f}')

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
    print(f'\nTest set: Average loss: {test_loss:.4f}, '
          f'Accuracy: {correct}/{len(test_loader.dataset)} ({accuracy:.0f}%)\n')

# 增加训练轮数
for epoch in range(1, 6):  # 训练五轮
    train(model, device, train_loader, optimizer, epoch)
    test(model, device, test_loader)

# 对抗攻击实现（FGSM方法）
def fgsm_attack(data, epsilon, data_grad, targeted=False):
    if targeted:
        perturbed_data = data - epsilon * data_grad.sign()
    else:
        perturbed_data = data + epsilon * data_grad.sign()
    
    # 调整 clamping 范围
    min_pixel_value = (0 - 0.1307) / 0.3081  # ≈ -0.4242
    max_pixel_value = (1 - 0.1307) / 0.3081  # ≈ 2.8215
    perturbed_data = torch.clamp(perturbed_data, min_pixel_value, max_pixel_value)
    return perturbed_data

# 非目标攻击和目标攻击的实验
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
    
    # 打印梯度信息
    print('Data grad max:', data_grad.max().item(), 'min:', data_grad.min().item())
    
    perturbed_data = fgsm_attack(data, epsilon, data_grad, targeted)
    
    # 打印扰动信息
    diff = perturbed_data - data
    print('Perturbation max:', diff.max().item(), 'min:', diff.min().item())
    
    return perturbed_data

# 显示图片
def imshow(img, title):
    img = img.detach().cpu().numpy().squeeze()
    plt.imshow(img, cmap="gray")
    plt.title(title)
    plt.show()

# 从测试集中选择数字为9的样本
for data, target in test_loader:
    if target.item() == 9:
        original_data = data
        original_label = target
        imshow(original_data, "Original Image - 9")
        break

# 调整 epsilon
epsilon = 0.6

# 非目标攻击 - 使其误识别为任何其他数字
perturbed_data = attack_image(
    model, device, original_data, original_label, epsilon, targeted=False
)
output = model(perturbed_data)
final_pred = output.argmax(dim=1, keepdim=True)
print(f'Original Label: 9, Predicted after Untargeted Attack: {final_pred.item()}')
imshow(perturbed_data, f"Perturbed Image (Untargeted Attack) - Predicted: {final_pred.item()}")

# 目标攻击 - 使其误识别为指定的数字，比如8
target_label = torch.tensor([8]).to(device)
perturbed_data_targeted = attack_image(
    model, device, original_data, original_label, epsilon, targeted=True, target_label=target_label
)
output = model(perturbed_data_targeted)
final_pred_targeted = output.argmax(dim=1, keepdim=True)
print(f'Original Label: 9, Predicted after Targeted Attack (Target: 8): {final_pred_targeted.item()}')
imshow(
    perturbed_data_targeted,
    f"Perturbed Image (Targeted Attack) - Predicted: {final_pred_targeted.item()}"
)
