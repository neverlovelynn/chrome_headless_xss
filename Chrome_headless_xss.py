#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2/7/18 下午3:29
# @Author  : fz
# @Site    :
# @File    : xss.py
# @Software: PyCharm


import json
import requests
import websocket
import time

# 递归解析json

def dict_generator(indict, pre=None):
    pre = pre[:] if pre else []
    if isinstance(indict, dict):
        for key, value in indict.items():
            if isinstance(value, dict):
                if len(value) == 0:
                    yield pre+[key, '{}']
                else:
                    for d in dict_generator(value, pre + [key]):
                        yield d
            elif isinstance(value, list):
                if len(value) == 0:
                    yield pre+[key, '[]']
                else:
                    dict_flag = 0
                    for v in value:
                        if isinstance(v, dict):
                            dict_flag = 1
                    if dict_flag ==1:
                        for v in value:
                            for d in dict_generator(v, pre + [key]):
                                yield d

                    else:
                        yield pre+[key, value]
            else:
                yield pre + [key, value]
    else:
        yield indict

# 解析json获得包含payload的node_id

def get_node_info(root, target):
    tmp = []

    def get_node_id(root, target, tmp):
        node_value = root.get('nodeValue')
        if target not in node_value:
            if 'children' in root:
                children = root.get('children')
                if children:
                    for item in children:
                        get_node_id(item, target=target, tmp=tmp)
        else:
            node_id = root.get('nodeId')
            node_backend_id = root.get('backendNodeId')
            dict_tmp = {"node_value": node_value, "node_id": node_id, "node_backend_id": node_backend_id}
            tmp.append(dict_tmp)

    get_node_id(root, target, tmp=tmp)

    return tmp




class ChromeHeadLess(object):
    def __init__(self, url, ip="127.0.0.1", port="9222", cookie="", post="", auth="", payload="", check_message=""):

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
        self.javascript_dialog_events = []
        self.payload = payload
        self.dom_result = []
        self.check_message =check_message
        self.request_id = []
        self.response_body = []
        chrome_web = "http://%s:%s/json/new" % (ip, port)
        try:
            response = requests.get(chrome_web)
            self.ws_url = response.json().get("webSocketDebuggerUrl")
            self.tab_id = response.json().get("id")
            self.soc = websocket.create_connection(self.ws_url)
            self.soc.settimeout(2)
        except Exception, e:
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

    # 对插入的自定义标签进行判断,如果存在则判断存在level2等级的xss

    def level_2_check(self, result_json, result_list):

        tmp_json = result_json

        for i in dict_generator(tmp_json):
            if i[-2] == 'localName' and i[-1] == 'webscan':

                if len(result_list) != 0:
                    if result_list[0]['level'] != '3':
                        result_list[0]['vul'] = 'xss'
                        result_list[0]['level'] = '2'
                    else:
                        pass

    # 判断payload是否存在dom树的nodeValue中
    def node_value_check(self, result_json, payload):
        flag =False
        tmp_json = result_json
        for i in dict_generator(tmp_json):
            if i[-2] == 'nodeValue' and payload in i[-1]:
                flag = True
        return flag




    # 对payload最后在html渲染后的结果，通过outHtml的结果判断是否在服务端进行了实体编码

    def level_1_check(self, payload, result_list):
        out_time = 4
        start_time = time.time()
        while (time.time() - start_time) < out_time:
            try:
                result = self.soc.recv()
                result_json = dict(json.loads(result))
                if '''"id":2324''' in result:
                    node_id_list =[]
                    tmp_node_id = get_node_info(result_json['result']['root'], self.payload)
                    for item in tmp_node_id:
                        node_id_list.append(item['node_id'])
                    print tmp_node_id
                    for item in node_id_list:
                        node_id = item
                        self.send_msg(id=2325, method="DOM.getOuterHTML", params={'nodeId': node_id})

                if '''"id":2325''' in result:
                    print result
                    if payload in result_json['result']['outerHTML']:
                        result_list[0]['vul'] = 'xss'
                        result_list[0]['level'] = '1'
                    else:
                        pass
            except Exception, e:
                self.error = e
                print self.error





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
                            "level": "0"
                        })
                    self.request_id.append(result_json["params"]['requestId'])
                    # self.send_msg()

                #  如果第一个返回包的content-type是json，则直接判断没有漏洞（忽略特定版本ie的情况）

                if "Network.responseReceived" in result:
                    self.response_body.append(result_json['params']['response'])
                    if 'application/json' in self.response_body[0]['headers']["Content-Type"]:
                        break

                elif "Page.javascriptDialogOpening" in result:
                    # hook alert
                    if result_json["params"] not in self.javascript_dialog_events:
                        self.javascript_dialog_events.append(result_json["params"])

                        if result_json["params"]["message"] == self.check_message:
                            if result_json["params"]["url"] != 'about:blank':
                                for item in self.hook_urls:
                                    if item["url"] in result_json['params']['url']:
                                        item["vul"] = "xss"
                                        item["level"] = "3"
                                        break
                            else:
                                self.hook_urls[0]['vul']= "xss"
                                self.hook_urls[0]['level'] = "3"
                                break

                elif "Page.domContentEventFired" in result:
                    # dom加载完以后 执行on事件的javascript
                    self.send_msg(id=2323, method="Runtime.evaluate",
                                   params={"expression": "\nvar nodes = document.all;"
                                                         "\nfor(var i=0;i<nodes.length;i++){"
                                                         "\n    var attrs = nodes[i].attributes;"
                                                         "\n    for(var j=0;j<attrs.length;j++){"
                                                         "\n        attr_name = attrs[j].nodeName;"
                                                         "\n        attr_value = attrs[j].nodeValue.replace(/return.*;/g,'');"
                                                         "\n        if(attr_name.substr(0,2) == \"on\"){"
                                                         "\n            console.log(attrs[j].nodeName + ' : ' + attr_value);"
                                                         "\n            eval(attr_value);"
                                                         "\n        }"
                                                         "\n        if(attr_name == \"href\" || attr_name == \"formaction\"){"
                                                         "\n            console.log(attrs[j].nodeName + ' : ' + attr_value);"
                                                         "\n            javascript_code = attr_value.match(\"^javascript:(.*)\")"
                                                         "\n           if (javascript_code) {"
                                                         "\n               eval(javascript_code[0]);"
                                                         "\n           }"
                                                         "\n        }"
                                                         "\n    }"
                                                         "\n}"
                                                         "\n'ok';"})


                self.send_msg(id=2324, method="DOM.getDocument", params={"depth": -1})



                if'''"id":2324''' in result:

                    self.dom_result.append(result_json)

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

                # Executes querySelectorAll on a given node.

            self.get_chrome_msg()
            if self.dom_result:
                node_value_flag = False
                for item in self.dom_result:
                    self.level_2_check(item, self.hook_urls)
                    if self.node_value_check(item, self.payload):
                        node_value_flag = True

                if node_value_flag:
                    if self.hook_urls[0]['vul'] != 'xss' and self.hook_urls[0]['level'] == '0':
                        self.level_1_check(self.payload, self.hook_urls)
            self.close_tab()
        else:
            self.close_tab()
            self.error = "get websocket err!"

        return self.hook_urls[0], self.javascript_dialog_events, self.dom_result

if __name__ == '__main__':
    chrome_headless_drive = ChromeHeadLess(url="http://xss.php",
                                           ip="127.0.0.1", port="9222",
                                           cookie="",
                                           post="",
                                           auth="",
                                           payload='''test_test''',
                                           check_message="your_alert_touch")

    resutl = chrome_headless_drive.run()

    print resutl[0]
