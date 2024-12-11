import json

def read_and_write_jsonl(input_filename, output_filename, num_lines=1000):
    # 打开输入文件和输出文件
    with open(input_filename, 'r', encoding='utf-8') as infile, open(output_filename, 'w', encoding='utf-8') as outfile:
        # 读取前 num_lines 行并写入到输出文件
        for i, line in enumerate(infile):
            if i >= num_lines:
                break
            # 将读取的每一行转换为字典并写入输出文件
            json_data = json.loads(line)
            outfile.write(json.dumps(json_data, ensure_ascii=False) + '\n')

# 使用示例
input_filename = './4_Filter/data/results/CC-MAIN-2013-20_Bert.jsonl'  # 输入文件路径
output_filename = './test/demo.jsonl'  # 输出文件路径
read_and_write_jsonl(input_filename, output_filename, num_lines=1000)
