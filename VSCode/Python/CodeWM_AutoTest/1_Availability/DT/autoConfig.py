from aiAPI import *
import json
import re
import time
import os
import argparse

def getDependency(client:Client, filePath:str, lang:str, max_retries=3, retry_delay=2) -> Optional[Dict]:
    """
    获取依赖文件
    :param file_path: 文件路径
    :return: 依赖json
    """
    prompt = f"""
        请分析上面的{lang}代码，并输出依赖配置，以JSON格式返回。输出内容如下(**不包含任何其他内容！！！**)：
        ```json
        {{
            "jdk_version": "11", # 根据Java代码中使用的特性，推断合适的JDK版本。输出时请只包含版本号，例如 `11`
            "dependencies": [ # 根据Java代码中的所有外部库依赖，列出每个依赖的
                {{
                    "group": "com.example", # 依赖的 `groupId`
                    "artifact": "example-artifact", # 依赖的 `artifactId`
                    "version": "1.0.0" # 依赖的版本号
                }},
                ...
            ]
        }}
        ```
        请注意：
        - 如果使用的是标准JDK类库（如 `javax.swing`, `java.util` 等），可以不添加这些库。
        - 请确保每个依赖都有`group`, `artifact`, 和 `version` 字段。
        - 依赖项要尽可能全面，确保包含运行时所有必要的库。
    """
    retries = 0
    while retries < max_retries:
        try:
            deps = files_chat(client, Model.gpt4o_ca, [filePath], [prompt], StreamMode=True)
            # print(deps)
            match = re.search(r'```json(.*?)```', deps, re.DOTALL)
            if match:
                deps = match.group(1).strip()
                depsJson = json.loads(deps.replace("```json\n", "").replace("\n```", "").strip())
                return depsJson
            else:
                raise ValueError("No JSON content found in the response.")
        except Exception as e:
            retries += 1
            print(f"Error get {filePath} dependency: {e}")
            time.sleep(retry_delay)
    print("Max retries reached. Could not process the response successfully.")
    return None  # 如果达到最大重试次数仍然失败，返回 None


def genPOM(json_data, java_file_path):
    # 解析 JSON 数据
    dependencies = json_data.get('dependencies', [])
    jdk_version = json_data.get('jdk_version', '11')  # 默认为 JDK 11

    # 获取文件目录
    project_dir = os.path.dirname(java_file_path)
    # 获取文件名（带扩展名）
    file_name = os.path.basename(java_file_path)
    # 获取类名（去掉扩展名）
    class_name = os.path.splitext(file_name)[0]
    
    # Maven POM 模板
    pom_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
             http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    
    <groupId>com.example</groupId>
    <artifactId>{class_name}</artifactId>
    <version>1.0-SNAPSHOT</version>
    <packaging>jar</packaging>

    <properties>
        <maven.compiler.source>{jdk_version}</maven.compiler.source>
        <maven.compiler.target>{jdk_version}</maven.compiler.target>
    </properties>

    <dependencies>
'''

    # 为每个依赖添加到 pom.xml
    for dep in dependencies:
        group = dep.get('group', '')
        artifact = dep.get('artifact', '')
        version = dep.get('version', '')
        
        pom_content += f'''        <dependency>
            <groupId>{group}</groupId>
            <artifactId>{artifact}</artifactId>
            <version>{version}</version>
        </dependency>
'''

    # 关闭 dependencies 标签
    pom_content += '''    </dependencies>
</project>'''

    # 保存 pom.xml 文件到指定目录
    pom_file_path = os.path.join(project_dir, 'pom.xml')
    with open(pom_file_path, 'w') as pom_file:
        pom_file.write(pom_content)

    print(f'pom.xml has been generated at: {pom_file_path}')

def autoConfig(client:Client, filePath:str, lang:str):
    """
    TODO: 在文件对应目录下自动配置依赖
    :param client: aiAPI 客户端
    :param filePath: 文件路径
    :param lang: 语言类型
    """
    deps = getDependency(client, filePath, lang)
    if deps:
        genPOM(deps, filePath)
    else:
        raise RuntimeError("Failed to get dependencies from AI API.")

# if __name__ == '__main__':
#     # client = Client("./config/config.ini", "kimi")
#     client = Client("/home/zrz/.config/Personal_config/config_aiAPI.ini", "paid")
#     filePath = "/home/zrz/Projects/GitRepo/Repo/Python_Projects/VSCode/Python/CodeWM_AutoTest/results/stdDemo/CaroGame/CaroGame.java"
#     # deps = getDependency(client, filePath, "java")
#     # genPOM(deps, filePath)
#     autoConfig(client, filePath, "java")
#     # print(deps)

def main():
    # 使用 argparse 获取命令行参数
    parser = argparse.ArgumentParser(description='Process some inputs.')
    parser.add_argument('--filepath', type=str, help='Path to the file', required=True)
    parser.add_argument('--config', type=str, help='Path to the config file', default="/home/zrz/.config/Personal_config/config_aiAPI.ini")

    # 解析命令行参数
    args = parser.parse_args()

    # 使用传入的 filepath 参数
    clientPath = args.config
    filePath = args.filepath 

    # 继续你原来的逻辑
    client = Client(clientPath, "paid")
    autoConfig(client, filePath, "java")
    # print(deps)

if __name__ == '__main__':
    main()