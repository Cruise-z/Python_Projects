env dep:
conda create -n myMetagpt -c conda-forge python=3.9 pip=24.1.2 -y
conda create -n myMetagpt python=3.9

version: 0.8.2

切换分支:
git clone https://github.com/FoundationAgents/MetaGPT.git
cd MetaGPT/
抓全分支和所有 tag
git fetch --all --tags

看看 tag 名字是 v0.8.2 还是 0.8.2（仓库常用 v 前缀）
git tag -l | grep -E '^v?0\.8\.2$'

切到该tag:
git checkout tags/v0.8.2 -b metagpt-0.8.2

验证:
git describe --tags --always
git log -1 --oneline

修改代码:


以开发者模式安装:
pip install -e .