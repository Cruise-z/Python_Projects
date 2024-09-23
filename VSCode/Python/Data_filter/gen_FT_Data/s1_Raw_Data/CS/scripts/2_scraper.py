from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service  # Correct import for Service
from bs4 import BeautifulSoup
import nltk
# nltk.download('punkt_tab')
from nltk.tokenize import sent_tokenize
import json
import random
import time
import re
import os
import curses

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
        time.sleep(random.randint(1, 3)) # 等待页面加载
        if "404: Not Found" not in driver.page_source:
            return driver.page_source
        else:
            return None
    except Exception as e:
        print(f"An error occurred while scraping content for {url}: {e}", important=True)
    finally:
        driver.quit()
    return None

def testscrape(content:str):
    with open("./test.txt", 'w') as file:
        file.write(content)

## TODO:文本清理函数
def clean_text(Content:str):
    if not Content:
        return None 
    # TODO：使用 BeautifulSoup 解析 HTML 并提取纯文本
    soup = BeautifulSoup(Content, 'html.parser')
    # 获取文章名
    title = soup.title
    # 查找 <meta name="description"> 标签，并获取其 content 属性值
    description_meta = soup.find('meta', {'name': 'description'})
    description = description_meta['content'] if description_meta else ''
    # *:提取<div data-testid="article-base-body-content">
    # !:只查找匹配'data-testid'字段为'article-base-body-content'的标签部分
    # !:不能提取<div data-module="content" class="ContentModule-Wrapper">(存在多个)
    content_div = soup.find('div', {'data-testid': 'article-base-body-content'})
    content = content_div.prettify() if content_div else ''
    summary_div = soup.find('p', {'data-testid': 'article-summary'})
    summary = summary_div.prettify() if summary_div else ''
    # TODO：对获得的文章部分进一步清洗
    soup = BeautifulSoup(f"{title}: {description}{content}{summary}", 'html.parser')
    # 删除所有 <a> 标签，但保留其内部的文本
    for a_tag in soup.find_all('a'):
        a_tag.unwrap()
    # 删除所有广告和其他无用的标签，例如 <div> 中带有特定的 class 或 id
    for ad_tag in soup.find_all(['div', 'span'], {'class': ['Ad', 'Ad_pos_300_1v_article', 'Ad_pos_native_1v', 'Ad_pos_video_v', 'Ad_pos_reveal_1v']}):
        ad_tag.decompose()  # 完全移除广告
    # 保留其他标签中的文本，并去除标签
    for tag in soup.find_all(True):  # 查找所有 HTML 标签
        tag.unwrap()
    # TODO：提取清理后的纯文本处理为标准段落
    cleaned_text = soup.get_text()
    # 分割文本为句子
    sentences = sent_tokenize(cleaned_text)
    # 处理句子
    cleaned_sentences = [
        re.sub(r'\s+([.,:;!?])', r'\1', ' '.join(sentence.split())) 
        for sentence in sentences
    ]
    paragraph = ' '.join(cleaned_sentences)
    return paragraph

def test_url(url:str):
    content = scrape(url)
    article = clean_text(content)
    print(article)

## TODO:主要运行逻辑
def process(stage:str):
    work_dir = './gen_FT_Data/s1_Raw_Data/CS'
    article_dir = work_dir + '/articles'
    # 网站主页面
    website = 'https://www.darkreading.com'
    urls_dir = f"{work_dir}/urls.json"
    log_dir = f"{work_dir}/log.json"
    with open(urls_dir, 'r') as urlsfile:
        urlsdata = json.load(urlsfile)
    for item in urlsdata['urls']:
        article_url = f"{website}{item}"
        # TODO:得到文件写入路径
        # 提取目录和文件名: 去掉开头的 '/'，并分割路径为各级目录和文件名
        path_parts = item.strip('/').split('/')
        # 所有部分除了最后一个作为目录
        directory_path = os.path.join(article_dir, *path_parts[:-1])
        file_name = path_parts[-1] + '.txt'  # 最后一部分作为文件名
        file_path = os.path.join(directory_path, file_name)
        # TODO:读取log.json文件内容
        with open(log_dir, 'r') as logfile:
            data = json.load(logfile)
        if stage == 'scraping':
        # !:爬虫未完成时运行代码[未爬取全部url/'article_fail'表项不为空]
            # TODO:判断文章是否已经成功爬取
            if article_url in data['article_succ']:
                print(f"{article_url}已被成功提取过！")
                continue
            content = scrape(article_url)
        elif stage == 'finished':
        # !:爬虫结束后运行代码[选取已爬取过小文件重新爬取，确保'article_fail'表项为空]
            if not os.path.isfile(file_path) or os.path.getsize(file_path) < 500:
                content = scrape(article_url)
            else:
                continue
        if content:
            article = clean_text(content)
            os.makedirs(directory_path, exist_ok=True)
            with open(file_path, 'w') as file:  #覆写文件
                file.write(article)
            # TODO:对文件大小判断是否属于可疑文件(未完整提取)
            if os.path.getsize(file_path) > 50:
                data['article_succ'].append(article_url)
                # TODO:成功提取后若文件处于可疑/失败列表中则移除
                if article_url in data['article_susp']:
                    data['article_susp'].remove(article_url)
                elif article_url in data['article_fail']:
                    data['article_fail'].remove(article_url)
                print(f"get article success!:\n{article_url}")
            else:
                if article_url not in data['article_susp']:
                    data['article_susp'].append(article_url)
                if article_url in data['article_succ']:
                    data['article_succ'].remove(article_url)
                print(f"文件'{item}'大小过小:{os.path.getsize(file_path)}B", important=True)
        else:
            data['article_fail'].append(article_url)
            print(f"get article failed:{article_url}", important=True)
        with open(log_dir, 'r+') as logfile:
            logfile.seek(0)
            json.dump(data, logfile, indent=4)
            logfile.truncate()
    return 

# TODO:优化终端输出函数，使用[curses]替代[print]输出
def main(stdscr, Hlines, stage:str):
    # 初始清屏
    stdscr.clear()
    # 定义窗口的高度和宽度
    height, width = stdscr.getmaxyx()
    # 存储常规输出
    regular_output = []
    # 存储重点输出内容
    important_output = [""] * Hlines  # 预先分配 Hlines 行的空间
    # TODO:重定义print函数
    def print_to_curses(*args, important=False):
        nonlocal height, width, regular_output, important_output
        # 每次输出前更新窗口大小
        new_height, new_width = stdscr.getmaxyx()
        if new_height != height or new_width != width:
            height, width = new_height, new_width
            curses.resizeterm(height, width)
            stdscr.clear()  # 清除屏幕，适应新的窗口大小
        message = ' '.join(str(arg) for arg in args)
        # 分割消息以处理内部换行符
        lines = message.split('\n')
        if important:
            if len(important_output) + len(lines) > Hlines:
                diff = len(important_output) + len(lines) - Hlines
                important_output = important_output[diff:]
            important_output.extend(lines)
        else:
            regular_output.extend(lines)
            if len(regular_output) > height - Hlines:
                regular_output = regular_output[len(lines):]
        # 刷新输出窗口
        stdscr.erase()  # 更高效的清屏方式
        # 输出常规信息
        for idx, line in enumerate(regular_output):
            if idx < height - Hlines:
                try:  # 确保行内容适应宽度
                    stdscr.addstr(idx, 0, line[:width-1])
                except:
                    pass  # 忽略添加字符串时超出边界的错误
        # 输出重要信息
        base_line = height - Hlines
        for i, line in enumerate(important_output):
            if base_line + i < height:
                try:  # 确保行内容适应宽度
                    stdscr.addstr(base_line + i, 0, line[:width-1], curses.A_BOLD)
                except curses.error:
                    pass  # 忽略添加字符串时超出边界的错误
        stdscr.refresh()
    # TODO:替换原来的print函数
    global print
    original_print = print
    print = print_to_curses
    # TODO:运行实际爬虫处理函数
    try:
        process(stage=stage)  # 假设 process 是你实际运行的函数
    finally:
        # 恢复原来的 print 函数
        print = original_print
        stdscr.clear()
        stdscr.refresh()


curses.wrapper(main, 9, 'scraping')

