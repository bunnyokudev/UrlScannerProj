from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import socket, ipaddress, requests


app = Flask(__name__, template_folder='templates', static_folder='static')

@app.route('/')
def index():
    # diagnostic info
    print("=== RUNNING APP ===")
    return render_template("index.html")

def is_valid_url(u):
    try:
        p = urlparse(u)
        return p.scheme in ('http','https') and bool(p.netloc)
    except:
        return False

def hostname_allows(u):
    # resolve and reject private/loopback addresses (basic SSRF protection)
    try:
        hostname = urlparse(u).hostname
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            ip = info[4][0]
            if ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback:
                return False, f"resolved to private/loopback IP {ip}"
        return True, None
    except Exception as e:
        return False, f"DNS/resolution error: {e}"
@app.route('/scan_url', methods=['POST'])
def scan_url():
    data = request.get_json(silent=True)
    if not data or 'url' not in data:
        return jsonify(error='missing url'), 400

    url = data['url'].strip()
    if not is_valid_url(url):
        return jsonify(error='invalid url'), 400

    ok, reason = hostname_allows(url)
    if not ok:
        return jsonify(result='UNSAFE', reason=reason), 200

    # fetch small amount with timeouts; simple heuristic checks
    try:
        r = requests.get(url, timeout=(5,7), stream=True, headers={"User-Agent":"SimpleScanner/1.0"})
        # read up to 50 KB
        MAX = 50_000
        content = b''
        for chunk in r.iter_content(chunk_size=4096):
            if not chunk:
                break
            content += chunk
            if len(content) >= MAX:
                break
        text = content.decode('utf-8', errors='replace').lower()
    except requests.exceptions.RequestException as e:
        return jsonify(result='UNSAFE', reason=f'fetch error: {e}'), 200

    # simple heuristics for "unsafe" content
    suspicious = ['<iframe', '<script src=', 'eval(', 'document.write(', 'onerror=', 'malware', 'phishing', 'download.exe']
    for s in suspicious:
        if s in text:
            return jsonify(result='UNSAFE', reason=f'found suspicious pattern: {s}'), 200

    if r.status_code >= 400:
        return jsonify(result='UNSAFE', reason=f'http status {r.status_code}'), 200

    return jsonify(result='SAFE'), 200


if __name__ == "__main__":
    app.run(debug=True)
