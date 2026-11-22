# Test fixture: deliberately vulnerable code. Every flagged line is asserted in test/code-scan.test.mjs.
import subprocess, os, pickle, hashlib, random, requests, yaml, tempfile
from flask import request


def query(cur, name):
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    cur.execute(f"SELECT * FROM t WHERE id = {name}")
    sql = "SELECT * FROM x WHERE a = " + name
    cur.execute(sql)
    cur.execute("SELECT * FROM users WHERE id = %s", (name,))  # safe: bound parameter


def run(cmd, data):
    subprocess.run("ls " + cmd, shell=True)
    os.system("ls " + cmd)
    os.system("ls")  # constant command
    eval(data)
    pickle.loads(data)
    yaml.load(data)
    requests.get("https://x", verify=False)
    hashlib.md5(data)
    token = random.randint(0, 99999)
    open(request.args.get("f"))
    tempfile.mktemp()
    connect(host="h", password="hunter2hunter2")


def bad(a=[]):
    try:
        pass
    except Exception:
        pass
    if a == None:
        return 1


app.run(debug=True)
