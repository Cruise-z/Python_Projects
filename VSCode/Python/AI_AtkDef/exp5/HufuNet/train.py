# -*- coding: utf-8 -*
'''Train base models to later be pruned'''
from __future__ import print_function

import torch
import torch.nn as nn
import torch.optim as optim
import torch.optim.lr_scheduler as lr_scheduler
from torch.utils.data import DataLoader

import torchvision
import torchvision.transforms as transforms

import os
os.chdir("./exp5/HufuNet")
import json
import argparse

from models import *
from utils  import *
from tqdm   import tqdm


torch.backends.cudnn.enabled = False

frozen_seed()
parser = argparse.ArgumentParser(description='PyTorch MNIST Training')
parser.add_argument('--model',      default='VGG', help='resnet9/18/34/50, wrn_40_2/_16_2/_40_1')
parser.add_argument('--data_loc',   default='/disk/scratch/datasets/MNIST', type=str)
parser.add_argument('--checkpoint', default='VGG', type=str)
parser.add_argument('--load_from', default=None, type=str)
parser.add_argument('--GPU', default='0,1', type=str,help='GPU to use')
parser.add_argument('--epochs',     default=100, type=int)
parser.add_argument('--finetune',     default=0, type=int)
parser.add_argument('--lr',         default=0.0005)
parser.add_argument('--lr_decay_ratio', default=0.2, type=float, help='learning rate decay')
parser.add_argument('--weight_decay', default=0.0005, type=float)
args = parser.parse_args()
print(args)

device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
if torch.cuda.is_available():
    os.environ["CUDA_VISIBLE_DEVICES"]=args.GPU

global error_history

models = {'VGG' : vgg(),
          'FLenet': flenet(),
          'ResNet18': ResNet18(),
          'ResNet34':ResNet34(),
          'googlenet':googlenet()}
model = models[args.model]

if(args.finetune == 1):
    model.load_state_dict(torch.load('./checkpoints/'+args.load_from+'.t7')['net'])

if torch.cuda.is_available():
    model = model.cuda()
    if torch.cuda.device_count() > 1:
        model = nn.DataParallel(model)
model.to(device)

transform = transforms.Compose([transforms.Resize(32),transforms.ToTensor()])
batch_size = 32

transform_train = transforms.Compose([
    transforms.RandomCrop(32, padding=4),
    transforms.RandomHorizontalFlip(),
    transforms.ToTensor(),
    transforms.Normalize((0.4914, 0.4822, 0.4465), (0.2023, 0.1994, 0.2010)),
])
transform_test = transforms.Compose([
    transforms.ToTensor(),
    transforms.Normalize((0.4914, 0.4822, 0.4465), (0.2023, 0.1994, 0.2010)),
])

train_dataset = torchvision.datasets.CIFAR10(root='./data', train=True,download = True, transform=transform_train)
test_dataset = torchvision.datasets.CIFAR10(root='./data', train=False,download = True, transform=transform_test)

trainloader = DataLoader(train_dataset, batch_size=batch_size)
testloader = DataLoader(test_dataset, batch_size=batch_size)

finetune_trainset, finetune_testset = torch.utils.data.random_split(train_dataset,[int(len(train_dataset)*0.8), int(len(train_dataset)*0.2)])
finetune_trainloader = DataLoader(finetune_trainset, batch_size=batch_size)
finetune_testloader = DataLoader(finetune_testset, batch_size=batch_size)

optimizer = optim.Adam([w for name, w in model.named_parameters() if not 'mask' in name], lr=args.lr, betas=(0.9, 0.99))
scheduler = lr_scheduler.CosineAnnealingLR(optimizer,args.epochs, eta_min=1e-10)
criterion = nn.CrossEntropyLoss()
if(args.finetune == 0):
    trainloader_ = trainloader
    testloader_ = testloader
else:
    trainloader_ = finetune_trainloader
    testloader_ = finetune_testloader

validate_ori(model, -1, testloader_, criterion)
error_history = []
for epoch in tqdm(range(args.epochs)):
    train(model, trainloader_, criterion, optimizer)
    scheduler.step()
    validate_ori(model, epoch, testloader_, criterion,args.checkpoint)
















