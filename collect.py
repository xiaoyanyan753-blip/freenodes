#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""抓取公开免费节点 -> 去重 -> 用 mihomo 实测延迟和下载速度 -> 输出 free.yaml"""
import os, re, sys, json, base64, random, subprocess, time, urllib.request, urllib.parse
from concurrent.futures import ThreadPoolExecutor
import yaml

MAX_CAND = int(os.getenv("MAX_CAND", "4000"))    # 最多测多少个候选
DELAY_MAX = int(os.getenv("DELAY_MAX", "1500"))  # 延迟超过多少毫秒淘汰
SPEED_TOP = int(os.getenv("SPEED_TOP", "40"))    # 延迟最低的前多少个做测速
MIN_SPEED = float(os.getenv("MIN_SPEED", "0.5")) # 最低下载速度 MB/s
KEEP = int(os.getenv("KEEP", "30"))              # 最终保留多少个
API, MIXED = "http://127.0.0.1:19090", 17890
HERE = os.path.dirname(os.path.abspath(__file__))


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
    t = t.strip()
    if "proxies:" in t:
        try:
            d = yaml.safe_load(t)
            if isinstance(d, dict) and isinstance(d.get("proxies"), list):
                return [p for p in d["proxies"] if isinstance(p, dict) and p.get("server")
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
                    out.append(p)
            except Exception:
                pass
    return out


def fetch(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "clash.meta"})
        nodes = from_text(urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "ignore"))
        return url, nodes, None
    except Exception as e:
        return url, [], str(e)[:60]


def key(p):
    return (p["type"], str(p["server"]).lower(), int(p["port"]), str(p.get("uuid") or p.get("password") or ""))


def start_mihomo(nodes):
    """启动 mihomo；若因个别节点配置不合法而失败，按报错序号剔除后重试。"""
    for _ in range(40):
        for i, p in enumerate(nodes):
            p["name"] = "n%d" % i
        cfg = {"mixed-port": MIXED, "external-controller": "127.0.0.1:19090", "log-level": "info",
               "mode": "rule", "proxies": nodes,
               "proxy-groups": [{"name": "SEL", "type": "select", "proxies": [p["name"] for p in nodes]}],
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
                return proc, nodes
            except Exception:
                if proc.poll() is not None:
                    break
        proc.kill()
        log = open("/tmp/mh/log.txt", errors="ignore").read()
        m = re.search(r"proxy (\d+)", log)
        print("mihomo 启动失败：", log[-300:])
        if m and int(m.group(1)) < len(nodes):
            del nodes[int(m.group(1))]
        else:
            raise SystemExit("mihomo 无法启动")
    raise SystemExit("mihomo 无法启动")


def delay(name):
    try:
        u = "%s/proxies/%s/delay?url=http%%3A%%2F%%2Fwww.gstatic.com%%2Fgenerate_204&timeout=5000" % (
            API, urllib.parse.quote(name))
        return json.loads(urllib.request.urlopen(u, timeout=10).read())["delay"]
    except Exception:
        return None


def speed(name):
    try:
        req = urllib.request.Request(API + "/proxies/SEL", data=json.dumps({"name": name}).encode(), method="PUT")
        urllib.request.urlopen(req, timeout=10).read()
        r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{speed_download}", "-m", "10",
                            "-x", "http://127.0.0.1:%d" % MIXED,
                            "https://speed.cloudflare.com/__down?bytes=30000000"],
                           capture_output=True, text=True)
        return float(r.stdout or 0) / 1048576
    except Exception:
        return 0.0


def notify(text):
    t, c = os.getenv("TG_TOKEN"), os.getenv("TG_CHAT")
    if not (t and c):
        return
    try:
        data = urllib.parse.urlencode({"chat_id": c, "text": text}).encode()
        urllib.request.urlopen(urllib.request.Request("https://api.telegram.org/bot%s/sendMessage" % t, data=data),
                               timeout=20)
    except Exception as e:
        print("通知失败", e)


class NoAlias(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def main():
    urls = [x.strip() for x in open(os.path.join(HERE, "sources.txt"), encoding="utf-8")
            if x.strip() and not x.strip().startswith("#")]
    seen, nodes, stat = set(), [], []
    with ThreadPoolExecutor(8) as ex:
        for url, got, err in ex.map(fetch, urls):
            new = 0
            for p in got:
                k = key(p)
                if k not in seen:
                    seen.add(k)
                    nodes.append(p)
                    new += 1
            stat.append("%s | 解析%d 新增%d %s" % (url.split("/")[-3] if url.count("/") > 3 else url,
                                                  len(got), new, ("失败:" + err) if err else ""))
    print("\n".join(stat))
    random.shuffle(nodes)
    nodes = nodes[:MAX_CAND]
    total = len(nodes)
    print("候选节点", total)
    if total == 0:
        notify("⚠️ 免费节点更新：所有来源都没抓到节点")
        raise SystemExit(0)
    proc, nodes = start_mihomo(nodes)
    try:
        with ThreadPoolExecutor(64) as ex:
            ds = list(ex.map(delay, [p["name"] for p in nodes]))
        alive = sorted([(d, p) for d, p in zip(ds, nodes) if d and d <= DELAY_MAX], key=lambda x: x[0])
        print("延迟合格", len(alive))
        res = []
        for d, p in alive[:SPEED_TOP]:
            s = speed(p["name"])
            print(p["name"], d, "ms", round(s, 2), "MB/s")
            if s >= MIN_SPEED:
                res.append((s, d, p))
    finally:
        proc.kill()
    res.sort(key=lambda x: -x[0])
    res = res[:KEEP]
    report = ["# 更新报告", "", "时间(UTC): " + time.strftime("%Y-%m-%d %H:%M"), "",
              "候选 %d，延迟合格 %d，最终保留 %d" % (total, len(alive), len(res)), "", "## 来源"] + ["- " + s for s in stat]
    open(os.path.join(HERE, "report.md"), "w", encoding="utf-8").write("\n".join(report) + "\n")
    if len(res) < 3:
        notify("⚠️ 免费节点更新：合格节点只有 %d 个，保留上一次的结果" % len(res))
        return
    out = []
    for i, (s, d, p) in enumerate(res, 1):
        p = dict(p)
        p["name"] = "免费%02d-%.1fMB-%dms" % (i, s, d)
        out.append(p)
    with open(os.path.join(HERE, "free.yaml"), "w", encoding="utf-8") as f:
        yaml.dump({"proxies": out}, f, Dumper=NoAlias, allow_unicode=True, sort_keys=False)
    notify("✅ 免费节点已更新：候选%d → 保留%d 个，最快 %.1f MB/s（%dms）" % (total, len(out), res[0][0], res[0][1]))


if __name__ == "__main__":
    main()
