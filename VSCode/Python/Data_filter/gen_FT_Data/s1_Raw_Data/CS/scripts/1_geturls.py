from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service  # Correct import for Service
from bs4 import BeautifulSoup
import os
import json
import random
import time

# Set Chrome options
chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument("--headless")  # Uncomment this for headless mode
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--disable-dev-shm-usage")
chrome_options.add_argument("--proxy-server=http://127.0.0.1:7897")
chrome_options.add_argument("--user-data-dir=/home/zrz/.config/google-chrome/Default")
# Initialize WebDriver
service = Service(ChromeDriverManager().install())  # Use Service with ChromeDriverManager

## TODO:爬虫驱动函数
def scrape(url:str):
    driver = webdriver.Chrome(service=service, options=chrome_options)
    try:
        driver.get(url)
        time.sleep(random.randint(2, 5)) # 等待页面加载
        if "404: Not Found" not in driver.page_source:
            return driver.page_source
        else:
            return None
    except Exception as e:
        print(f"An error occurred while scraping content for {url}: {e}")
    finally:
        driver.quit()
    return None

## TODO:筛选链接函数
def articleurl(urlpage:str):
    # 使用 BeautifulSoup 解析 HTML 内容
    soup = BeautifulSoup(urlpage, 'html.parser')
    # 查找所有具有 data-testid="preview-default-title" 的 <a> 标签
    links = soup.find_all('a', attrs={'data-testid': 'preview-default-title'})
    # 提取所有 <a> 标签的 href 属性
    hrefs = [link['href'] for link in links]
    return hrefs

## TODO:获得所有文章链接
def geturls():
    work_dir = './gen_FT_Data/s1_Raw_Data/CS'
    # 创建log.json文件记录错误日志
    log_dir = f"{work_dir}/log.json"
    if not os.path.exists(log_dir):
        with open(log_dir, 'w') as file:
            json.dump({'urlpage_succ': [],
                       'urlpage_failed': [],
                       'article_succ': [],
                       'article_failed': [],
                       }, file)
    # 创建log.json文件记录错误日志
    urls_dir = f"{work_dir}/urls.json"
    if not os.path.exists(urls_dir):
        with open(urls_dir, 'w') as file:
            json.dump({'urls': []}, file)
    # 网站主页面
    website = 'https://www.darkreading.com'
    # 该网站下不同网安领域文章的分类与分类栏下的页数
    cls = {
        '/cybersecurity-operations':122,
        '/cybersecurity-operations/perimeter':52,
        '/cybersecurity-operations/physical-security':5,
        '/cybersecurity-operations/cybersecurity-careers':18,
        '/cybersecurity-operations/identity-access-management-security':7,
        '/cyber-risk':411,
        '/cyber-risk/data-privacy':10,
        '/endpoint-security':97,
        '/endpoint-security/mobile-security':24,
        '/endpoint-security/remote-workforce':9,
        '/ics-ot-security':20,
        '/ics-ot-security/iot':11,
        '/vulnerabilities-threats':194,
        '/vulnerabilities-threats/insider-threats':3,
        '/cloud-security':73,
        '/threat-intelligence':75,
        '/application-security':81,
        '/cybersecurity-analytics':81,
        '/cyberattacks-data-breaches':220,
    }
    for key, value in cls.items():
        for page in range(1, value+1):
            urlpage = f"{website}{key}?page={page}"
            print(f"当前urlpage:{urlpage}")
            # 判断这个urlpage是否被成功提取过
            with open(log_dir, 'r+') as logfile:
                data = json.load(logfile)
            if urlpage in data['urlpage_succ']:
                print(f"{urlpage}已被成功提取过！")
                continue
            # 爬取urlpage
            content = scrape(urlpage)
            # 若成功提取urlpage内容
            if content:
                with open(log_dir, 'r+') as logfile:
                    # 记录该urlpage被成功提取
                    data['urlpage_succ'].append(urlpage)
                    logfile.seek(0)
                    json.dump(data, logfile, indent=4)
                    logfile.truncate()
                # 提取urlpage中的urls至urls.json文件
                urls = articleurl(content)
                with open(urls_dir, 'r+') as urlsfile:
                    data = json.load(urlsfile)
                    for url in urls:
                        if url not in data['urls']:
                            data['urls'].append(url)
                        else:
                            print(f"{url}已被重复记录过")
                    urlsfile.seek(0)
                    json.dump(data, urlsfile, indent=4)
                    urlsfile.truncate()
                print("成功提取urls")


geturls()