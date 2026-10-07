"""
Flask /checkid —— 抓包后填入本文件，校验 ms_id
- 成功 -> 200
- 失败 -> 403
"""

from flask import Flask, request, jsonify
import requests, json

app = Flask(__name__)

# 抓包获取后填入
ZHIHU_URL = ""
HEADERS = {}


@app.route("/checkid", methods=["GET"])
def checkid():
    ms_id = request.args.get("ms_id", "").strip()
    if not ms_id:
        return jsonify({"ok": False, "msg": "缺少 ms_id 参数"}), 400
    if not ZHIHU_URL or not HEADERS:
        return jsonify({"ok": False, "msg": "请先抓包，把 URL 与请求头填入本文件"}), 400

    headers = dict(HEADERS)
    headers["x-ms-id"] = ms_id

    try:
        resp = requests.get(ZHIHU_URL, headers=headers, timeout=15)
    except Exception:
        return jsonify({"ok": False, "msg": "失败"}), 403

    if resp.status_code == 200:
        try:
            data = json.loads(resp.text)
        except Exception:
            data = None

        if isinstance(data, dict) and ("data" in data or "paging" in data):
            return jsonify({"ok": True, "msg": "成功"}), 200

    return jsonify({"ok": False, "msg": "失败"}), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
