#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2/7/18 下午3:29
# @Author  : fz
# @Site    :
# @File    : url_location.py
# @Software: PyCharm


import json
import requests
import websocket
import time


def check_url_location(result_list, payload):

    list_len = len(result_list)
    tmp_list = result_list
    i = 1
    if list_len != 0:
        while (i <list_len):
           if tmp_list[i]['url'].startswith(payload):
               tmp_list[0]['vul'] = 'url_location'
           i += 1
    else:
        pass
    return tmp_list[0]

class ChromeHeadLess(object):
    def __init__(self, url, ip="127.0.0.1", port="9222", cookie="", post="", auth="", payload =""):
        """
        初始化
        :param url: 请求url
        :param ip: ChromeHeadless的server ip
        :param port: ChromeHeadless的server 端口
        :param cookie: 请求cookie
        :param post:  请求post Chrome的api不支持
        :param auth:  请求 authorization
        """
        self.url = url
        self.cookie = cookie
        self.post = post
        self.auth = auth
        self.ip = ip
        self.port = port
        self.tab_id = ""
        self.ws_url = ""
        self.hook_urls = []
        self.error = ""
        self.soc = None
        # self.javascript_dialog_events = []
        self.payload = payload
        # self.dom_result = []
        chrome_web = "http://%s:%s/json/new" % (ip, port)
        try:
            response = requests.get(chrome_web)
            self.ws_url = response.json().get("webSocketDebuggerUrl")
            self.tab_id = response.json().get("id")
            self.soc = websocket.create_connection(self.ws_url)
            self.soc.settimeout(2)
            # print(self.ws_url, self.tab_id)
        except Exception, e:
            # print "ERROR:%s" % e
            self.error = str(e)

    def close_tab(self):
        """
        关闭tab
        :return:
        """
        try:
            requests.get("http://%s:%s/json/close/%s" % (self.ip, self.port, self.tab_id))
        except Exception, e:
            #print "ERROR:%s" % e
            self.error = str(e)

    def get_tab_list(self):
        '''
        获取当前teb_list
        :return:
        '''

        try:
            response = requests.get("http://%s:%s/json" % (self.ip, self.port))
            tem_str = response.content
            table_list = json.loads(tem_str)
        except Exception, e:
            self.error = str(e)

        return table_list

    def send_msg(self, id, method, params):
        """
        给ChromeHeadless的server 发执行命令
        :param id:
        :param method:
        :param params:
        :return:
        """
        navcom = json.dumps({
            "id": id,
            "method": method,
            "params": params
        })
        self.soc.send(navcom)

    def get_chrome_msg(self):
        """
        循环监听
        :return:
        """
        # 对整体请求设置最大延迟时间，
        out_time = 4
        start_time = time.time()

        while (time.time() - start_time) < out_time:
            try:
                result = self.soc.recv()
                result_json = dict(json.loads(result))

                if "Network.requestWillBeSent" in result:
                    # hook url
                    if result_json["params"]["request"]["url"] not in self.hook_urls:
                        if "postData" in result_json["params"]["request"]:
                            post = result_json["params"]["request"]["postData"]
                        else:
                            post = ""
                        self.hook_urls.append({
                            "url": result_json["params"]["request"]["url"],
                            "method": result_json["params"]["request"]["method"],
                            "post": post,
                            "vul": "",
                        })

            except Exception, e:
                self.error = e
                print self.error



    def run(self):
        if self.soc:

            # 设置http header
            (self.send_msg(id=1, method="Network.setExtraHTTPHeaders", params={"headers": {
                "authorization": self.auth,
                "Cookie": self.cookie,
                "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36"}}))

            # 启用网络跟踪，现在将网络事件传递给客户端
            self.send_msg(id=2, method="Network.enable", params={})

            # Enables page domain notifications.
            self.send_msg(id=3, method="Page.enable", params={})

            # Enables reporting of execution contexts creation by means of executionContextCreated event. When the
            # reporting gets enabled the event will be sent immediately for each existing execution context.
            self.send_msg(id=4, method="Runtime.enable", params={})

            # Navigates current page to the given URL.

            if self.post != "":
                (self.send_msg(id=6, method="Runtime.evaluate",
                               params={"expression": "httpRequest = new XMLHttpRequest();"
                                                     "\nhttpRequest.open(\"POST\",\"%s\",true);"
                                                     "\nhttpRequest.setRequestHeader(\"Content-type\",\"application/x-www-form-urlencoded\")"
                                                     "\nhttpRequest.onreadystatechange = function (){"
                                                     "\nif (httpRequest.readyState == 4 && httpRequest.status == 200) {"
                                                     "\n        document.write(httpRequest.responseText);"
                                                     "\n  }"
                                                     "\n}"
                                                     "\nhttpRequest.send(\"%s\");"
                                                     "\n'ok';"
                                                     "" % (self.url, self.post)}))

            else:
                self.send_msg(id=6, method="Page.navigate", params={"url": self.url})

            self.get_chrome_msg()

            self.close_tab()
        else:
            self.close_tab()
            self.error = "get websocket err!"

        scan_result = check_url_location(self.hook_urls, self.payload)

        return scan_result, self.hook_urls

if __name__ == '__main__':
    chrome_headless_drive = ChromeHeadLess (url="http://url_jump.html?url=http://www.baidu.com\\url_location.com",
                                               ip="127.0.0.1", port="9222",
                                               cookie="",
                                               post="",
                                               auth="",
                                               payload="http://www.baidu.com")

    test = chrome_headless_drive.run()
    print test[0]





