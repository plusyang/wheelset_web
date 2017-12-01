# encoding:utf-8
import threading


class MyThread(threading.Thread):

    def __init__(self,func=None,args=()):
        super(MyThread,self).__init__()
        self.func = func
        self.args = args

    def run(self):
        self.result = self.func(*self.args)

    def get_result(self):
        try:
            return self.result  # 如果子线程不使用join方法，此处可能会报没有self.result的错误
        except Exception:
            return None
