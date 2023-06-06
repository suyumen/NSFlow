from flask import Flask, render_template, request
from scapy.all import *
from flows import parse_pcap
app = Flask(__name__)

# 首页，上传pcap文件
@app.route("/")
def index():
    return render_template("index.html")

# 处理上传的pcap文件
@app.route("/process_file", methods=["POST"])
def process_file():
    # 获取上传的文件
    file = request.files["file"]

    # 解析pcap文件
    streams = parse_pcap(file)

    # 将流的信息传入html页面展示
    return render_template("result.html", streams=streams)

if __name__ == '__main__':
    app.run(debug=True)
