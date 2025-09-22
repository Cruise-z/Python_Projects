# 操作指南

## 环境依赖

```bash
conda create -n myMetagpt -c conda-forge python=3.9 pip=24.1.2 -y
conda create -n myMetagpt python=3.9
```

### `Metagpt`版本：

> version: 0.8.2
>
> ```bash
> $ git log -1 --oneline
> df9bc185 (HEAD -> metagpt-0.8.2, tag: v0.8.2) Merge pull request #1732 from XiangJinyu/main
> ```

## 快速使用

### 下载`git`仓库：

```bash
git clone https://github.com/FoundationAgents/MetaGPT.git
```

### 切换分支：

```bash
# 进入仓库根目录
cd MetaGPT/
# 抓全分支和所有 tag
git fetch --all --tags
# 看看 tag 名字是 v0.8.2 还是 0.8.2（仓库常用 v 前缀）
git tag -l | grep -E '^v?0\.8\.2$'
# 切到该tag
git checkout tags/v0.8.2 -b metagpt-0.8.2

# 验证
git describe --tags --always
git log -1 --oneline
```

### 修改代码：

将本路径下的`./metagpt`文件夹内的相关文件替换到下载的仓库中即可

### 安装：

#### 开发者模式

在`MetaGPT`仓库根目录中执行：

```bash
pip install -e .
```

即可