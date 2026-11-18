#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitHub 端（v3）：抓取公开来源 -> 解析 -> 去重 -> 存活检测 -> 按国家分配候选池 pool.yaml
这里【不测速、不做可用性结论】——GitHub 机房在美国，测出来对苏州没意义。
真正的"苏州电信线路实测"由路由器上的 suzhou.py 完成，它只测这里产出的候选池。
"""
import os, re, sys, socket, json, base64, random, subprocess, time, hashlib, ipaddress
import urllib.request, urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import yaml

MAX_CAND = int(os.getenv("MAX_CAND", "8000"))
DELAY_MAX = int(os.getenv("DELAY_MAX", "3500"))   # 只是剔除死节点，所以很宽松
POOL_QUOTA = {"SG": 250, "JP": 300, "TW": 150, "US": 400, "HK": 150, "GB": 100, "DE": 100}
WILD_MAX = int(os.getenv("WILD_MAX", "600"))       # Cloudflare 前置节点（真实出口国家不明），交给路由器去验证
API, MIXED = "http://127.0.0.1:19090", 17890
HERE = os.path.dirname(os.path.abspath(__file__))
T0 = time.time()


# ---------------- 解析 ----------------
def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore")


def q1(qs, k, d=""):
    return qs.get(k, [d])[0]


def transport(p, net, path, host, svc):
    if net == "ws":
        p["network"] = "ws"
        p["ws-opts"] = {"path": path or "/", "headers": {"Host": host} if host else {}}
    elif net == "grpc":
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name": svc or ""}
    elif net not in ("tcp", "", "none", None):
        return False
    return True


def p_vmess(l):
    j = json.loads(b64d(l[8:].split("#")[0]))
    p = {"name": "x", "type": "vmess", "server": j["add"], "port": int(j["port"]), "uuid": j["id"],
         "alterId": int(j.get("aid") or 0), "cipher": j.get("scy") or "auto", "udp": True}
    if j.get("tls") in ("tls", True, "1"):
        p["tls"] = True
        p["skip-cert-verify"] = True
        sni = j.get("sni") or j.get("host")
        if sni:
            p["servername"] = sni
    if not transport(p, j.get("net"), j.get("path"), j.get("host"), j.get("path")):
        return None
    return p


def p_vless(l):
    u = urllib.parse.urlsplit(l)
    qs = urllib.parse.parse_qs(u.query)
    p = {"name": "x", "type": "vless", "server": u.hostname, "port": u.port,
         "uuid": urllib.parse.unquote(u.username or ""), "udp": True}
    sec = q1(qs, "security")
    if sec in ("tls", "reality"):
        p["tls"] = True
        p["skip-cert-verify"] = True
        p["client-fingerprint"] = q1(qs, "fp") or "chrome"
        sni = q1(qs, "sni") or q1(qs, "host")
        if sni:
            p["servername"] = sni
        if sec == "reality":
            if not q1(qs, "pbk"):
                return None
            p["reality-opts"] = {"public-key": q1(qs, "pbk"), "short-id": q1(qs, "sid")}
    if q1(qs, "flow"):
        p["flow"] = q1(qs, "flow")
    if not transport(p, q1(qs, "type", "tcp"), q1(qs, "path"), q1(qs, "host"), q1(qs, "serviceName")):
        return None
    return p


def p_trojan(l):
    u = urllib.parse.urlsplit(l)
    qs = urllib.parse.parse_qs(u.query)
    p = {"name": "x", "type": "trojan", "server": u.hostname, "port": u.port,
         "password": urllib.parse.unquote(u.username or ""), "udp": True, "skip-cert-verify": True}
    sni = q1(qs, "sni") or q1(qs, "peer")
    if sni:
        p["sni"] = sni
    if not transport(p, q1(qs, "type", "tcp"), q1(qs, "path"), q1(qs, "host"), q1(qs, "serviceName")):
        return None
    return p


def p_ss(l):
    main, _, query = l[5:].split("#")[0].partition("?")
    if "@" in main:
        ui, hp = main.rsplit("@", 1)
        ui = urllib.parse.unquote(ui) if ":" in ui else b64d(ui)
    else:
        ui, hp = b64d(main).rsplit("@", 1)
    if "plugin" in query:
        return None
    method, pwd = ui.split(":", 1)
    host, port = hp.rstrip("/").rsplit(":", 1)
    return {"name": "x", "type": "ss", "server": host.strip("[]"), "port": int(port),
            "cipher": method, "password": pwd, "udp": True}


def p_hy2(l):
    u = urllib.parse.urlsplit(l)
    qs = urllib.parse.parse_qs(u.query)
    p = {"name": "x", "type": "hysteria2", "server": u.hostname, "port": u.port,
         "password": urllib.parse.unquote(u.netloc.rsplit("@", 1)[0]) if "@" in u.netloc else "",
         "skip-cert-verify": True}
    if q1(qs, "sni"):
        p["sni"] = q1(qs, "sni")
    if q1(qs, "obfs"):
        p["obfs"] = q1(qs, "obfs")
        p["obfs-password"] = q1(qs, "obfs-password")
    return p


PARSERS = {"vmess": p_vmess, "vless": p_vless, "trojan": p_trojan, "ss": p_ss,
           "hysteria2": p_hy2, "hy2": p_hy2}
YAML_TYPES = {"vmess", "vless", "trojan", "ss", "hysteria2"}


def from_text(t):
    """返回 [(节点dict, 是否来自yaml)]"""
    t = t.strip()
    if "proxies:" in t:
        try:
            d = yaml.safe_load(t)
            if isinstance(d, dict) and isinstance(d.get("proxies"), list):
                return [(p, True) for p in d["proxies"] if isinstance(p, dict) and p.get("server")
                        and p.get("port") and p.get("type") in YAML_TYPES]
        except Exception:
            pass
    if "://" not in t:
        try:
            t = b64d(t)
        except Exception:
            return []
    out = []
    for line in t.splitlines():
        line = line.strip()
        sch = line.split("://", 1)[0].lower() if "://" in line else ""
        if sch in PARSERS:
            try:
                p = PARSERS[sch](line)
                if p and p.get("server") and 0 < int(p["port"]) < 65536:
                    out.append((p, False))
            except Exception:
                pass
    return out


def label(url):
    parts = url.split("/")
    if ("githubusercontent" in url or "github.com" in url) and len(parts) > 5:
        return "%s/%s:%s" % (parts[3], parts[4], parts[-1])
    return parts[2] if len(parts) > 2 else url


def fetch(url):
    err = ""
    for _ in range(2):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "clash.meta"})
            raw = urllib.request.urlopen(req, timeout=30).read(30 * 1024 * 1024)
            return url, from_text(raw.decode("utf-8", "ignore")), None
        except Exception as e:
            err = str(e)[:60]
            time.sleep(2)
    return url, [], err


# ---------------- 过滤和键 ----------------
def bad_host(h):
    h = h.strip().lower()
    if not h:
        return True
    try:
        return not ipaddress.ip_address(h).is_global
    except ValueError:
        return h == "localhost" or h.endswith((".local", ".internal", ".lan"))


def cred(p):
    return str(p.get("uuid") or p.get("password") or "")


def key(p):
    return (p["type"], str(p["server"]).lower(), int(p["port"]), cred(p))


def netkey(h):
    h = str(h).lower()
    try:
        ip = ipaddress.ip_address(h)
        if ip.version == 4:
            return ".".join(h.split(".")[:3])
        return str(ipaddress.ip_network(h + "/48", strict=False))
    except ValueError:
        return ".".join(h.split(".")[-2:])


# ---------------- mihomo（只用来判断节点是否还活着） ----------------
def start_mihomo(items):
    for _ in range(60):
        for i, it in enumerate(items):
            it["p"]["name"] = "n%d" % i
        cfg = {"mixed-port": MIXED, "external-controller": "127.0.0.1:19090", "log-level": "info",
               "unified-delay": True, "mode": "rule", "proxies": [it["p"] for it in items],
               "proxy-groups": [{"name": "SEL", "type": "select", "proxies": [it["p"]["name"] for it in items]}],
               "rules": ["MATCH,SEL"]}
        os.makedirs("/tmp/mh", exist_ok=True)
        with open("/tmp/mh/config.yaml", "w") as f:
            yaml.safe_dump(cfg, f, allow_unicode=True)
        lf = open("/tmp/mh/log.txt", "w")
        proc = subprocess.Popen([os.path.join(HERE, "mihomo"), "-d", "/tmp/mh"], stdout=lf, stderr=lf)
        for _ in range(30):
            time.sleep(1)
            try:
                urllib.request.urlopen(API + "/version", timeout=2).read()
                return proc, items
            except Exception:
                if proc.poll() is not None:
                    break
        proc.kill()
        logtxt = open("/tmp/mh/log.txt", errors="ignore").read()
        print("mihomo 启动失败：", logtxt[-300:])
        m = re.search(r"proxy (\d+)", logtxt)
        if m and int(m.group(1)) < len(items):
            del items[int(m.group(1))]
        else:
            if not any(it["y"] for it in items):
                raise SystemExit("mihomo 无法启动")
            items = [it for it in items if not it["y"]]
    raise SystemExit("mihomo 无法启动")


def delay(name):
    try:
        u = "%s/proxies/%s/delay?url=http%%3A%%2F%%2Fwww.gstatic.com%%2Fgenerate_204&timeout=5000" % (
            API, urllib.parse.quote(name))
        return json.loads(urllib.request.urlopen(u, timeout=10).read())["delay"]
    except Exception:
        return None


def geo_batch(items):
    """按服务器IP批量查国家和ASN（每次100个）。"""
    def res(it):
        h = str(it["p"]["server"])
        try:
            ipaddress.ip_address(h)
            return h
        except ValueError:
            try:
                return socket.getaddrinfo(h, None, socket.AF_INET)[0][4][0]
            except Exception:
                return None
    with ThreadPoolExecutor(32) as ex:
        ips = list(ex.map(res, items))
    uniq = sorted({x for x in ips if x and ":" not in x})
    if len(uniq) > 3000:
        uniq = random.sample(uniq, 3000)
    info = {}
    for i in range(0, len(uniq), 100):
        try:
            req = urllib.request.Request("http://ip-api.com/batch?fields=status,countryCode,as,query",
                                         data=json.dumps(uniq[i:i + 100]).encode(),
                                         headers={"Content-Type": "application/json"})
            for j in json.loads(urllib.request.urlopen(req, timeout=20).read()):
                if j.get("status") == "success":
                    info[j["query"]] = (j["countryCode"], (j.get("as") or "?").split()[0])
        except Exception as e:
            print("geo 查询失败", str(e)[:50])
        time.sleep(4.5)
    for it, ip in zip(items, ips):
        it["gcc"], it["gasn"] = info.get(ip, ("XX", "?"))


class NoAlias(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def load_pool(path):
    try:
        d = yaml.safe_load(open(path, encoding="utf-8"))
        return [p for p in d["proxies"] if isinstance(p, dict)]
    except Exception:
        return []


def build_pool(alive):
    """每个目标国家按配额取候选；Cloudflare 前置节点单独放进 WILD。同凭据/同网段限量。"""
    pools = {cc: [] for cc in POOL_QUOTA}
    wild = []
    cnt = {cc: Counter() for cc in POOL_QUOTA}
    wcnt = Counter()
    for it in sorted(alive, key=lambda x: (0 if x["prior"] else 1, x["d"])):
        p, cc = it["p"], it["gcc"]
        if it["gasn"] == "AS13335":
            target, cap, cn = wild, WILD_MAX, wcnt
        elif cc in POOL_QUOTA:
            target, cap, cn = pools[cc], POOL_QUOTA[cc], cnt[cc]
        else:
            continue
        if len(target) >= cap:
            continue
        kc, kn = ("c", cred(p)), ("n", netkey(p["server"]))
        if cn[kc] >= 3 or cn[kn] >= 6:
            continue
        cn[kc] += 1
        cn[kn] += 1
        target.append(it)
    return pools, wild


def main():
    urls = [x.strip() for x in open(os.path.join(HERE, "sources.txt"), encoding="utf-8")
            if x.strip() and not x.strip().startswith("#")]
    seen, items, stat = set(), [], []

    def add(p, src, isy, prior=False):
        try:
            p["port"] = int(p["port"])
            k = key(p)
        except Exception:
            return False
        if bad_host(str(p["server"])) or k in seen:
            return False
        seen.add(k)
        items.append({"p": p, "src": src, "y": isy, "k": k, "prior": prior})
        return True

    for p in load_pool(os.path.join(HERE, "pool.yaml")):   # 上次的候选池先放进来，保持稳定
        add(p, -1, True, True)
    n_prior = len(items)
    with ThreadPoolExecutor(8) as ex:
        results = list(ex.map(fetch, urls))
    for idx, (url, got, err) in enumerate(results):
        new = sum(1 for p, isy in got if add(p, idx, isy))
        stat.append((label(url), len(got), new, err))
        print("%-52s 解析%-6d 新增%-6d %s" % (label(url), len(got), new, ("失败:" + err) if err else ""))

    prior = [it for it in items if it["prior"]]
    buckets = {}
    for it in items:
        if not it["prior"]:
            buckets.setdefault(it["src"], []).append(it)
    for b in buckets.values():
        random.shuffle(b)
    sel = list(prior)
    while len(sel) < MAX_CAND and any(buckets.values()):
        for b in buckets.values():
            if b and len(sel) < MAX_CAND:
                sel.append(b.pop())
    total = len(sel)
    print("候选 %d（上次候选池 %d）" % (total, n_prior))
    if total == 0:
        raise SystemExit("所有来源都没抓到节点")

    proc, sel = start_mihomo(sel)
    try:
        with ThreadPoolExecutor(48) as ex:
            ds = list(ex.map(delay, [it["p"]["name"] for it in sel]))
    finally:
        proc.kill()
    alive = []
    for d, it in zip(ds, sel):
        it["d"] = d
        if d and d <= DELAY_MAX:
            alive.append(it)
    print("存活", len(alive))
    geo_batch(alive)
    pools, wild = build_pool(alive)

    out, rows = [], []
    for cc, lst in list(pools.items()) + [("WILD", wild)]:
        for i, it in enumerate(lst, 1):
            p = dict(it["p"])
            p["name"] = "%s-%03d" % (cc, i)
            out.append(p)
        rows.append("%s %d" % (cc, len(lst)))
    bj = time.strftime("%Y-%m-%d %H:%M", time.gmtime(time.time() + 8 * 3600))
    rep = ["# 候选池报告", "", "北京时间: " + bj, "",
           "候选 %d（上次池 %d）→ 存活 %d → 入池 %d" % (total, n_prior, len(alive), len(out)),
           "各国入池数量：" + "，".join(rows), "",
           "> 这里只做存活检测和国家归类。可用性、速度、AI/YouTube/GitHub 连通都由路由器在苏州线路上实测。",
           "", "## 来源"]
    rep += ["- %s：解析 %d，新增 %d %s" % (a, b, c, ("❌" + e) if e else "") for a, b, c, e in stat]
    open(os.path.join(HERE, "report.md"), "w", encoding="utf-8").write("\n".join(rep) + "\n")
    if len(out) < 40:
        print("入池太少(%d)，保留上一次的 pool.yaml" % len(out))
        return
    with open(os.path.join(HERE, "pool.yaml"), "w", encoding="utf-8") as f:
        yaml.dump({"proxies": out}, f, Dumper=NoAlias, allow_unicode=True, sort_keys=False)
    print("pool.yaml 已写入 %d 个节点；用时 %d 秒" % (len(out), time.time() - T0))


if __name__ == "__main__":
    main()
