from jinja2 import Template
import sys
from Stream import *


def generate_html(streams):
    # 读取HTML模板文件
    with open('index.html', 'r', encoding='utf-8') as f:
        template_file = f.read()
        # 使用Jinja2模板引擎渲染HTML模板
        template = Template(template_file)
        html_content = template.render(streams=streams)
        # 将渲染结果写入HTML文件
    with open('result.html', 'w', encoding='utf-8') as f:
        f.write(html_content)


if __name__ == '__main__':
    file = sys.argv[1]
    generate_html(parse_pcap(file))
