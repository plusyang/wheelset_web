# encoding:utf-8
import time
import json
import urllib2
import random

if __name__ == "__main__":
    while True:
        req = urllib2.Request("http://127.0.0.1:5000/data/insert_data")
        f = urllib2.urlopen(req)
        response = f.read()
        print response
        f.close()
        time.sleep(1)
