import os

import torch
import numpy as np
from torch.nn import CrossEntropyLoss
import tqdm
from torch.utils.data import DataLoader, TensorDataset
import matplotlib.pyplot as plt
from data import get_data
import cv2

device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")


def save_trigger(mask,trigger,epoch,label):
    trigger = trigger.clone().cpu().detach().numpy()
    trigger = np.transpose(trigger, (1, 2, 0))*255
    cv2.imwrite('./trigger/trigger_'+str(label)+'_'+str(epoch)+'.png',trigger)
    mask = mask.clone().cpu().detach().numpy()*255
    cv2.imwrite('./trigger/mask_'+str(label)+'_'+str(epoch)+'.png',mask)


def train(model, target_label, train_loader, param):
    """对某一target_label的逆向trigger过程"""

    print("\nProcessing label: {}".format(target_label))

    # 设置初始的随机trigger，以及mask
    width, height = param["image_size"]
    trigger = torch.rand((3, width, height), requires_grad=True)
    trigger = trigger.to(device).detach().requires_grad_(True)
    mask = torch.rand((width, height), requires_grad=True)
    mask = mask.to(device).detach().requires_grad_(True)

    # 优化器的优化参数为trigger以及mask
    optimizer = torch.optim.Adam([{"params": trigger}, {"params": mask}], lr=0.005)
    criterion = CrossEntropyLoss()
    model.to(device)
    model.eval()

    # 训练参数
    Epochs = param["Epochs"]
    lamda = param["lamda"]

    # 记录mask的norm值，初始值为无穷大
    min_norm = np.inf
    min_norm_count = 0

    # 遍历训练集数据，训练Epochs轮
    for epoch in range(Epochs):
        norm = 0.0
        for images, _ in tqdm.tqdm(train_loader, desc='Epoch %3d' % (epoch + 1)):
            optimizer.zero_grad()
            images = images.to(device)

            # 把trigger和mask添加到图片上
            trojan_images = (1 - torch.unsqueeze(mask, dim=0)) * images + torch.unsqueeze(mask, dim=0) * trigger

            # 一般训练过程
            y_pred = model(trojan_images)
            y_target = torch.full((y_pred.size(0),), target_label, dtype=torch.long).to(device)
            loss = criterion(y_pred, y_target) + lamda * torch.sum(torch.abs(mask))
            loss.backward()
            optimizer.step()

            # 计算mask的norm
            with torch.no_grad():
                # 防止trigger和norm越界
                torch.clip_(trigger, 0, 1)
                torch.clip_(mask, 0, 1)
                norm = torch.sum(torch.abs(mask))
        print("norm: {}".format(norm))
        save_trigger(mask, trigger, epoch, target_label)

        # early stop
        if norm < min_norm:
            min_norm = norm
            min_norm_count = 0
        else:
            min_norm_count += 1

        if min_norm_count > 5:
            break

    return trigger.cpu(), mask.cpu()


def reverse_engineer():
    param = {
        "dataset": "cifar10",
        "Epochs": 20,  # 每个类别进行trigger逆向训练的轮数
        "batch_size": 64,
        "lamda": 0.01,
        "num_classes": 10,
        "image_size": (32, 32)
    }

    # 加载模型和数据集
    #model = torch.load('model_cifar10.pkl').to(device)
    model = torch.load('model_cifar10.pkl',map_location=torch.device('cpu')).to(device)
    _, _, x_test, y_test = get_data(param)
    x_test, y_test = torch.from_numpy(x_test) / 255., torch.from_numpy(y_test)
    train_loader = DataLoader(TensorDataset(x_test, y_test), batch_size=param["batch_size"], shuffle=False)

    # 开始逆向，依次遍历每个标签
    norm_list = []
    for label in range(param["num_classes"]):
        # 对每个标签，逆向对应的trigger和mask
        trigger, mask = train(model, label, train_loader, param)
        norm_list.append(mask.sum().item())

        # 将逆向出的trigger和mask图像保存
        trigger = trigger.cpu().detach().numpy()
        trigger = np.transpose(trigger, (1, 2, 0))
        plt.axis("off")
        # plt.imshow(trigger)
        plt.savefig('mask/trigger_{}.png'.format(label), bbox_inches='tight', pad_inches=0.0)

        mask = mask.cpu().detach().numpy()
        plt.axis("off")
        # plt.imshow(mask)
        plt.savefig('mask/mask_{}.png'.format(label), bbox_inches='tight', pad_inches=0.0)

    print(norm_list)



reverse_engineer()