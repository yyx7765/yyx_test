### 目录结构
- api 存放接口的目录
  - endpoint 封装了各个模块所对应接口的调用方法
    - __init__.py
    - monitor_manage.py 存放监控管理tab的接口
    - user_login.py  用户登录的接口
  - models  想存放请求数据和响应数据模型，用于测试和验证
- case 存放测试用例
  - eq_manage 管理模块用例
    - monitor_manage  存放监控管理tab的case
      - test_case.py  测试用例
      - data.py  测试数据
  - conftest.py *pytest运行时的配置文件，用于定义fixture、hook等函数*
- config 存放全局配置文件
  - environment 环境配置文件
    - eq_manage_host.py 管理模块host
- core 存放核心基类
  - case_base.py case基类
  - login_context.py 
- log 存放日志
- reports 存放测试报告
- utils 公共工具包
  - exception 存放一些异常状态返回code或者msg
    - assertation.py  断言异常返回
    - base.py
    - error.py 错误状态码
  - httpcall.py 封装接口请求方法
  - myassert.py   断言工具，封装常用的断言方法。
  - logger  日志工具，生成日志的方法
  - report_utils  报告工具，生成报告的方法，推送报告的方法
  - 。。。
- venv 虚拟环境
- .gitignore 用于忽略一些垃圾文件
- pytest.ini  pytest的配置文件，配置pytest的运行参数，如测试目录、日志级别等。
- README.md  项目说明文档
- requirements.txt  项目的依赖文件，列出所有需要的Python包及其版本

代码如下：
#api/endpoints/monitor_manage.py
# -- coding: utf-8 -*-
from utils.logger import logger as Logger
from config.environment.eq_manage_host import APIUdache
from utils.httpcall import MyHttp



class MonitorManageDomain(object):
    
    
    __URL_monitorScreen = "monitorScreen/getVehicleOnlineCount"
    
    
    
    def getVehicleOnlineCount(self,headers:dict = None, data:dict = None, *args, **kwargs) -> dict:
        """获取在线车辆"""
        method = "post"
        url = self.__URL_monitorScreen
        
        #接口调用
        domain = APIUdache.TEST04
        r = MyHttp(host=domain).send_request( method=method,url=url, headers=headers, data=data, *args, **kwargs)
        if r.status_code != 200:
            Logger.error(f"获取在线车辆失败，状态码：{r.status_code}, 响应：{r.text}")
        return r.json()       


# api/endpoints/user_login.py
from utils.httpcall import MyHttp
from config.environment.eq_manage_host import APIUdache
from utils.logger import logger as Logger

class UserLogin(object):

    __URL_login = "login"

    def user_login(self,username,password,headers:dict = None,*args,**kwargs) -> dict:
        method = "post"
        url = self.__URL_login
        data = {}

        domain = APIUdache.TEST04
        r = MyHttp(host=domain).send_request(method=method,headers=headers,url=url,data=data,*args,**kwargs)

        if  r.status_code != 200:
            Logger.error(f"用户登录失败，状态码：{r.status_code},响应{r.text}")

        try:
            return r.json()["token"]
        except ValueError:
            Logger.error(f"不正确的json,内容为{r.text}")
            return {}

# case/eq_manage/monitor_manage/data.py

MonitorScreenData = {
    "orgId": "d96c5d295def42419642429cf6cd9095"
}


# case/eq_manage/monitor_manage/test_case.py
# -*- coding: utf-8 -*-
import allure
import pytest

from api.endpoints.monitor_manage import MonitorManageDomain
from core.case_base import TestCaseBase
from . import data

allure.tag("case维护人：xxx")
class TestMonitorManage(TestCaseBase):
    
    @allure.description("监控大屏接口测试") # 必填，case描述
    # @pytest.mark.skipif("全局变量里定义的环境标识，标注只在线下或者线上跑，选择性的跑")
    def test_monitor_screen(self):
        # 示例，通过这种方式也可以指定环境
        # globalvar.env_tag = EnvTag.DEV_SIM
        # globalvar.env_num = "120"
        # globalvar.env = "osim174-v"

        with allure.step("监控大屏接口测试"):
            # 调用监控大屏接口
            r = MonitorManageDomain().getVehicleOnlineCount(
                headers= self.headers,
                data=data.MonitorScreenData
            )
            # 断言响应状态码和数据
            self.assert_is_superset(superset=r,subset={"error":0},recursive=False)





    def test_case_02(self):
        # 测试用例 02
        pass


# case/conftest.py
import pytest
from utils.logger import logger
from utils.report_utils import ReportUtils


@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
    """
    测试会话结束后生成Allure报告
    """
    allure_report_dir, allure_url= ReportUtils.generate_allure_report()
    webhook_url = "https://xxxxx"
    message = {
        "msg_type": "post",
        "content": {
        "post": {
            "zh_cn": {
                "title": "Allure报告生成啦，请及时查收",
                "content": [
                    [{
                        "tag": "text",
                        "text": "自动化报告: "
                    }, {
                        "tag": "a",
                        "text": "请查看",
                        "href": f"{allure_url}"
                    }, {
                        "tag": "at",
                        "user_id": "11111"
                    }]
                ]
            }
        }
    }
    }

    ReportUtils.sned_webhook(webhook_url,message)


@pytest.fixture(autouse=True)
def log_test_start_end(request):
    """在每个测试用例开始和结束时打印日志"""
    logger.info(f"Starting test: {request.node.name}")
    yield
    logger.info(f"Finished test: {request.node.name}")


#config/enviroment/eq_manage_host.py
# -*- coding: utf-8 -*-

class DomainBase(object):
    #定义测试环境的基础域名
    TEST04 = None
    TEST09 = None
    ONLINE_HLH = None

    def test04(self):
        return self.TEST04
    
    def test09(self):
        return self.TEST09
    

    # def get_domain(self): TODO:这里需要等扩充一个constant（常量）文件，定义环境的标识/case编写者等信息,现在先不用
    #     if env_tag == EnvTag.TEST04:
    #         return self.test04() 

class APIUdache(DomainBase):
    #具体的测试环境域名
    TEST01 = "https://xxx.xxx.xxx"
    TEST02 = "https://xxx.xxx.xxx"


class GlobalVariables(DomainBase):
    #定义全局变量
    TIMEOUT = 10
    USERNAME = "test"
    PASSWORD = "123456"
    COOKIE = "Sxxx"

    HEADERS = {
        "token" : "xxx"
    }



# core/case_base.py
# -*- coding: utf-8 -*-

import os
import pytest
import allure
import zlib

from utils.myassert import MyAssert
from config.environment.eq_manage_host import GlobalVariables
from api.endpoints.user_login import UserLogin


class TestCaseBase(MyAssert):
    headers = GlobalVariables().HEADERS

    @pytest.fixture(autouse=True) #autouse=True 表示该 fixture 会自动应用到所有继承 TestCaseBase 的测试用例类中。
    def setup_teardown(self): # setUp 的操作，在测试用例执行前获取 token
        self.get_token()
        yield
        #yield 语句之前的代码相当于 setUp 方法,之后的代码相当于 tearDown 方法,会在每个测试用例执行后执行
        #目前先pass

    # def get_caseid(self,f:str):
    #     """获取case id"""
    #     relpath = os.path.relpath(os.path.abspath(f),"")
    #     case_id = hex(zlib.crc32(bytes(relpath,encoding='UTF-8'))).lstrip("0x")
    #     return case_id
    def get_token(self):
        """获取token并设置到全局变量中"""
        login_domain = UserLogin()
        response = login_domain.user_login(GlobalVariables.USERNAME,GlobalVariables.PASSWORD)
        if "token" in response:
            GlobalVariables.HEADERS["token"] = response["token"]
        else:
            pytest.fail("登录失败，未获取到token")

# core/login_context.py
#-*- coding: utf-8 -*-

from api.endpoints.user_login import UserLogin
from config.environment.eq_manage_host import GlobalVariables
from utils.logger import logger as  Logger

class LoginContext: # 定义一个上下文管理器类，用于在登录状态下执行测试用例
    def __init__(self):
        self.login_domain = UserLogin() # 创建UserLogin类的实例

        self.headers = GlobalVariables.CheckLogin_HEADERS

    def __enter__(self):
        # 在进入上下文时执行登录操作
        try:
            response = self.login_domain.user_login()
            if response:
                self.headers['token'] = response # 若登录成功，将token设置到请求头中，并使用日志记录登录成功信息
                Logger.info("登录成功，获取到token")
            else:
                Logger.error("登录失败，未获取到token") 
                raise Exception("登录失败") # 若登录失败，抛出异常并记录错误信息
            return self # 返回上下文管理器实例
        except Exception as e:
            Logger.error(f"登录过程中发生异常：{e}")
            raise e # 抛出异常并记录错误信息
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # 在退出上下文时执行清理操作
        if exc_type is not None:
            Logger.error(f"退出上下文时发生异常：{exc_type.__name__}, 错误信息：{exc_val}, {exc_tb}")
        Logger.info("退出登录上下文") 
        return False # 返回False表示不抑制异常
    
# utils/exception/assertation.py
# -*- coding: utf-8 -*-
# @Function: 业务校验错误码

from utils.exception.base import Base
from utils.exception.error import AssertErrno


class AsserationException(Base):
    """AsserationException 类继承自 Base 异常类，定义了错误码和错误信息。可以通过传入不同的错误信息来定制异常。"""
    errno = AssertErrno.RESP_ERR #定义错误码
    errmsg = "assert err" #定义错误信息

    def __init__(self, errmsg: str = None):
        if errmsg:
            self.errmsg = errmsg

    def __str__(self):
        return self.errmsg


if __name__ == '__main__':
    print(AsserationException("test err"))
    a = AsserationException("test errno")
    print(a.errno)


# utils/exception/base.py
# -*- coding: utf-8 -*-


class Base(Exception):
    """Base 类继承自 Exception，并实现了 __init__ 和 __str__ 方法，用于抛出异常"""
    def __init__(self):
        raise Exception

    def __str__(self):
        raise Exception

# utils/exception/error.py
# -*- coding: utf-8 -*-
"""

    内部错误码号段：
    账号相关：10000~19999
    基础服务：20000~29999
    数据校验：30000~39999
"""
from enum import Enum


class BtpErrno(type):
    REDIS_ERR = 1001  # case不存在
    MYSQL_ERR = 1002  # case运行错误，需要重试
    HTTP_FAIL = 1003  # case运行错误，不需要重试


class AssertErrno(type):
    RESP_ERR = 30000


# utils/httpcall.py
# -*- coding: utf-8 -*-

import json
import requests
import allure
from utils.logger import logger as Logger
from config.environment.eq_manage_host import GlobalVariables



class HttpLog(object):
    def set_log(self):
        #定义日志参数
        log_params = ("service", "host", "url", "session", "method", "headers", "params", "data", "rstatus", "errmsg", "response", "response_header")
        log_str = "_com_dirpc_info"
        for key in log_params:
            if key in self.__dict__.keys():
                log_str = log_str + " ||" + str(key) + "=" + str(self.__dict__[key])
        Logger.info(log_str)

    def set_err_log(self):
        log_params = ("service", "host", "url", "session", "method", "headers", "params", "data", "rstatus", "errmsg", "response", "response_header")

        log_str = " _com_dirpc_info"
        for key in log_params:
            if key in self.__dict__.keys():
                log_str = log_str + "||" + str(key) + "=" + str(self.__dict__[key])

        Logger.info(log_str)
                
def allure_log(*args, **kwargs):

    url = ""
    if "url" in kwargs.keys():
        url = kwargs["url"]

    func = url.split('/')[-1]

    @allure.step("接口调用 {u}".format(u=url))
    def allure_log_2(*args, **kwargs):
        pass

    return allure_log_2(*args, **kwargs)

class MyHttp(HttpLog):
    # 请求数据
    service = None
    url = None
    host = ""
    method = None

    session = None
    headers = None
    params = None
    data = None

    # 返回数据
    status: str = ""
    response_header: str = ""
    response: str = ""

    # 异常
    e: str = ""

    def __init__(self, host:str,*args,**kwargs):

        self.host = host
        # self.service = service

    def send_request(self, headers:dict,  method:str, url:str, params:dict = None, data:dict = None, *args, **kwargs):
        """
        发送HTTP请求
        params，dict格式，作为url中的参数; data，dict格式，作为body参数
        headers： dict
        """
        self.url = url
        self.params = params
        self.data = data
        self.headers = GlobalVariables.HEADERS


        #接口调用
        if method == "get":
            r = self.get(*args,**kwargs)
        elif method == "post":
            r = self.post(*args,**kwargs)
        elif method == "put":
            r = self.put(*args,**kwargs)
        elif method == "delete":
            r = self.delete(*args,**kwargs)
        else:
            Logger.error("请求方式还不支持")
            return

        self.status = str(r.status_code)
        try:
            response = json.dumps(r.json())
        except Exception as e:
            response = r.content
        self.response = response
        self.response_header = str(r.headers)

        allure_log(url=self.url,body=self.dumps(self.data),params=json.dumps(self.params),response=self.response)
        self.set_log()
        return r

    def get(self, *args, **kwargs):
        self.method = "get"
        try:
            r = requests.get(url=self.host+self.url,params=self.params, data=self.data,  headers=self.headers, timeout=(1,10))
        except Exception as e:
            self.errmsg = e.__str__()
            self.set_err_log()
            raise Exception("请求失败: %s" % e)
        return r

    def post(self, *args, **kwargs):

        # 默认connect timeout=1s， read timeout=5s，后续优化成可定制
        try:
            r = requests.post(url=self.host+ self.url, params=self.params, data=self.data, headers=self.headers, timeout=(1, 5))
        except Exception as e:
            self.errmsg = e.__str__()
            self.set_err_log()
            raise Exception("请求失败: %s" % e)
        return r


if __name__ == "__main__":
    pass





        
# utils/logger.py
# -*- coding: utf-8 -*-

import os
import arrow
import logbook
from logbook import Logger, TimedRotatingFileHandler
from logbook.more import ColorizedStderrHandler


class MyLogger(object):
    run_log = None

    #定义日志存放目录
    log_dir = os.path.abspath(os.path.join(os.path.realpath(__file__), "../../log"))
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    def log_type(record: logbook.base.LogRecord, handler):
        #定义日志格式
        log = "[{level}][{date}][line={filename} +{lineno} function={func_name}] {msg}".format(
            date=arrow.now().format('YYYY-MM-DDTHH:mm:ss:SSSZ'),  # 日志时间
            level=record.level_name,  # 日志等级
            filename=record.filename,  # 文件名
            func_name=record.func_name,  # 函数名
            lineno=record.lineno,  # 行号
            msg=record.message  # 日志内容
        )
        return log

    # 输出到屏幕
    log_std = ColorizedStderrHandler(bubble=True)
    log_std.formatter = log_type

    # 输出到文件
    log_file = TimedRotatingFileHandler(
        os.path.join(log_dir, '%s.log' % 'log'), date_format='%Y%m%d%H', bubble=True, encoding='utf-8',
        timed_filename_for_current=False)
    log_file.formatter = log_type

    def __init__(self):
        run_log = Logger("script_log")
        logbook.set_datetime_format("local")

        run_log.handlers = []
        run_log.handlers.append(self.log_file)
        run_log.handlers.append(self.log_std)

        self.run_log = run_log

#创建日志实例  logger 供其他模块使用。
logger = MyLogger().run_log

if __name__ == '__main__':
    a = {"aaa": "sss"}
    logger.info(a)
    # logger.critical(a)


#utils/myassert.py

# -*- coding: utf-8 -*-

import json
import operator
from typing import Mapping, List, Any, Union, Dict
# from jsonpath_ng import parse
# from util.logger import logger
from utils.exception.assertation import AsserationException
# from util.report.allurestep import assert_step


class MyAssert(object):

    @classmethod
    def assert_is_superset(cls, superset: Union[List, Dict], subset: dict, recursive=True) -> bool:
        """
        校验subset中的内容在superset中是否存在  ***【即实际返回是否包含某个字段的期望返回】
        Args:
            superset: 父集合
            subset: 子集合
            recursive: 是否递归查询。如果为True，那么需要子集合中的内容在递归中的同一层级

        Eg: superset = {"b": 20, "c": 30, "a": {"m": 1, "n": 2}, "d": [{"p": 1, "q": 2}, {"x": 1, "y": 2}]}
            subset = {"b": 20, "c": 30}  -> return True
            subset = {"a": {"m": 1, "n": 2}}  -> return True
            subset = {"m": 1, "n": 2}  -> recursive=True: return True;  recursive=False: return False
            subset = {"p": 1, "q": 2}  -> recursive=True: return True;  recursive=False: return False
        """

        v = is_superset(superset=superset, subset=subset, recursive=recursive)

        if not v:
            raise AsserationException(  # raise用于在程序的指定位置手动抛出一个异常
                "assert is superset fail, superset:{superset}, subset:{subset}, recursive:{recursive}".format(
                    superset=json.dumps(superset), subset=subset, recursive=recursive)
            )

        return True

    @classmethod
    def assert_equal(cls, origin: Any, expect: Any) -> bool:
        """
        校验数据是否相等，支持任意类型
        """

        if origin != expect:
            raise AsserationException(
                "assert equal fail, origin:{origin} != expect:{expect}".format(
                    origin=origin, expect=expect)
            )

        return True

    @classmethod
    def assert_contain(cls, origin: str, expect: str) -> bool:
        """
        校验字符串是否包含，支持字符串类型
        """

        if expect not in origin:
            raise AsserationException(
                "assert contain fail, origin:{origin} dose not contain expect:{expect}".format(
                    origin=origin, expect=expect)
            )

        return True

    @classmethod
    def assert_not_equal(cls, origin: Any, expect: Any) -> bool:
        """
        校验数据是否不等，支持任意类型
        """

        if origin == expect:
            raise AsserationException(
                "assert not equal fail, origin:{origin} != expect:{expect}".format(
                    origin=origin, expect=expect)
            )

        return True

    @classmethod
    def assert_rule(cls, origin: Any, expect: Any, rule: str) -> bool:
        """
        指定校验方式，方式为字符串类型,
        """
        if str == type(origin):
            expect = str(expect)
        if rule == ">":
            if origin <= expect:
                raise AsserationException(
                    "assert failed, origin:{origin} != expect:{expect}".format(
                        origin=origin, expect=expect)
                )
        elif rule == ">=":
            if origin < expect:
                raise AsserationException(
                    "assert failed, origin:{origin} != expect:{expect}".format(
                        origin=origin, expect=expect)
                )
        elif rule == "<":
            if origin >= expect:
                raise AsserationException(
                    "assert failed, origin:{origin} != expect:{expect}".format(
                        origin=origin, expect=expect)
                )
        elif rule == "<=":
            if origin > expect:
                raise AsserationException(
                    "assert failed, origin:{origin} != expect:{expect}".format(
                        origin=origin, expect=expect)
                )

    @classmethod
    def assert_in(cls, origin: Any, expect: List) -> bool:
        """
        校验数据是否相等，支持任意类型
        """

        if origin not in expect:
            raise AsserationException(
                "assert equal fail, origin:{origin} != expect:{expect}".format(
                    origin=origin, expect=expect)
            )

        return True


def is_superset(superset: Union[List, Dict], subset: Mapping, recursive=True) -> bool:
    # 处理list
    if isinstance(superset, List):
        for super_value in superset:
            if isinstance(super_value, Dict) or isinstance(super_value, List):
                if is_superset(superset=super_value, subset=subset, recursive=True):
                    return True

    # 处理dict
    for key, value in subset.items():
        flag = 1
        # 如果本层内subset都存在，则return true
        if not operator.contains(superset, key) or superset[key] != value:
            flag = 0
            break
        if flag:
            return True

    if not recursive:
        return False

    # 递归
    for key, value in superset.items():
        if isinstance(value, Dict):
            if is_superset(superset=value, subset=subset, recursive=True):
                return True

        elif isinstance(value, List):
            for super_value in value:
                if isinstance(super_value, Dict) or isinstance(super_value, List):
                    if is_superset(superset=super_value, subset=subset, recursive=True):
                        return True

    return False


def is_superlist(superset: Union[List, Dict], subset: List, recursive=True) -> bool:
    pass


if __name__ == '__main__':
    actual_dict1 = {"b": 20, "c": 30, "a": {"m": 1, "n": 2}, "d": [{"p": 1, "q": 2}, {"x": 1, "y": 2}]}
    actual_dict2 = {"p": 1, "q": 2}
    actual_list = [{"x": 20, "b": 30, "a": {"m": 1, "n": 2}, "d": [{"p": 1, "q": 2}, {"x": 1, "y": 2}]},
                   {"b": 20, "c": 30, "a": {"m": 1, "n": 2}, "d": [{"p": 1, "q": 2}, {"x": 1, "y": 2}]}]

    print(MyAssert.assert_is_superset(superset=actual_dict2, subset=actual_dict1))
    # MyAssert.assert_with_path(origin=actual_dict, expect={"m": 1, "n": 2}, path="a")
    # MyAssert.assert_with_path(origin=actual_dict, expect=1, path="d[0].p")
    # MyAssert.assert_with_path(origin=actual_dict, expect=1, path="d[*].p")
    #
    # actual_list = [{"p": 1, "q": [1, 2, 3]}, {"x": 1, "y": 2}]
    # AssertDict.assert_with_path(origin=actual_list, expect=1, path="[*].p")
    # AssertDict.assert_with_path(origin=actual_list, expect=1, path="[*].q.[*]")

    # superset = {"data":{"baseConf":[{"cityId":1,"menuId":"bike","menuNumId":366,"openStatus":1,"submenuRange":[],"defaultSubmenu":"","id":228,"name":"Bike","iconFlipStatus":1,"isUpgradeLink":0,"link":"OneTravel://bike/entrance","linkText":"","menuType":0}]},"curVersion":"2531293461"}
    # superset = {"errno":0,"errmsg":"","curtime":1642571993,"data":{"menuList":[{"menuList":[{"menuId":"dache_anycar"}]}],"baseConf":[{"cityId":1,"menuId":"bike","menuNumId":366,"openStatus":1,"submenuRange":[],"defaultSubmenu":"","id":228,"name":"Bike","iconFlipStatus":1,"isUpgradeLink":0,"link":"OneTravel://bike/entrance","linkText":""}]},"curVersion":"2531293461"}
    # subset = {'menuId': 'bike', 'link': 'OneTravel://bike/entrance'}
    # r = is_superset(superset=superset, subset=subset)
    # r = is_superset2(superset=actual_list, subset={"p": 1, "q": 2})
    # print(r)


# utils/report_utils.py
import os
import subprocess
from datetime import datetime

import requests


class ReportUtils:
    @staticmethod  #定义一个静态方法，表示该方法不依赖于类的实例。
    def generate_allure_report():
        """
        生成Allure报告并启动Allure服务
        """
        # 定义报告目录
        allure_results_dir = os.path.join(os.path.dirname(__file__), "..", "reports", "allure-results")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        allure_report_dir = os.path.join(os.path.dirname(__file__), "..", "reports", f"allure-report-{timestamp}")

        # 检查 allure-results 目录是否存在
        if not os.path.exists(allure_results_dir):
            raise FileNotFoundError(f"Allure 结果目录不存在: {allure_results_dir}")

        # 检查 allure-results 目录是否为空
        if not os.listdir(allure_results_dir):
            raise ValueError(f"Allure 结果目录为空: {allure_results_dir}")

        # 生成Allure报告  --clean参数确保每次都是全新报告
        subprocess.call(f"allure generate {allure_results_dir} -o {allure_report_dir} --clean", shell=True)

        #返回生成的报告目录和URL
        return allure_report_dir,ReportUtils.get_allure_report_url(allure_report_dir)

        # 启动Allure服务
        # subprocess.call(f"allure open {allure_report_dir}", shell=True)

    @staticmethod
    def get_allure_report_url(allure_report_dir):
        """
            生成Allure报告的URL。
           :param allure_report_dir: Allure报告目录。
           :return: Allure报告的URL。
        """
        base_url = "http://localhost:63342"
        project_path = "/auto_api"
        report_path = os.path.relpath(allure_report_dir,os.path.join(os.path.dirname(__file__),".."))
        report_url = f"{base_url}{project_path}/{report_path}/index.html"
        return report_url

    @staticmethod
    def sned_webhook(webhook_url,message):
        payload = message
        response = requests.post(webhook_url,json=payload)
        if response.status_code == 200:
            print("报告向飞书发送成功")
        else:
            print(f"报告向飞书发送失败，status_code:{response.status_code}")

    @staticmethod
    def generate_timestamp():
        """
        生成时间戳，用于日志和报告
        """
        return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

