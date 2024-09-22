import pandas as pd
import json

csv_file = "owasp_top10.csv"
# 提取英文描述的函数
def extract_descriptions(data):

    # 检查 containers.cna.descriptions
    cna_descriptions = data.get("containers", {}).get("cna", {}).get("descriptions", [])
    for description in cna_descriptions:
        if description.get("lang") == "en":
            desc = description.get("value")

    return desc

def generate_output(csv_file_path):
    output_data = []
    chunk_iter = pd.read_csv(csv_file_path, chunksize=1)
    for chunk in chunk_iter:
        row = chunk.iloc[0]

        cwe_id = row['CWEid']
        cve_id = row['CVEid']
        commit_urls = row['commit_url']
        diff = row['filelist']

        parts = cve_id.split('-')
        year = parts[1]
        id = parts[2]
        id_dir = id[:-3] + "xxx"
        cve_file_path = f"cvelistV5/cves/{year}/{id_dir}/{cve_id}.json"
        with open(cve_file_path, 'r', encoding='utf-8') as file:
            json_data = json.load(file)
        description = extract_descriptions(data=json_data)
        output_dict = {"CVEid":cve_id, "CWEid":cwe_id, "commit_urls":commit_urls, "diff":diff, "desc":description}
        output_data.append(output_dict)

    with open('output_for_funcname.json', 'w') as file:
        json.dump(output_data, file, indent=4)
        print(f"Data written to output_for_funcname.json")
            
if __name__ == "__main__":
    generate_output(csv_file_path=csv_file)
