#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
抓取公开免费节点 -> 过滤去重 -> mihomo 实测 -> 多样化挑选 -> 输出 free.yaml
v2：来源均衡抽样 / 上次入选节点必复测 / 稳定性加分 / 出口国家和ASN去重 / Google·Telegram·AI 连通检测
"""
import os, re, sys, json, base64, random, subprocess, time, hashlib, ipaddress
import urllib.request, urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import yaml

# ---------------- 可调参数（也可在 workflow 里用环境变量覆盖） ----------------
MAX_CAND = int(os.getenv("MAX_CAND", "4000"))      # 最多测多少个候选
DELAY_MAX = int(os.getenv("DELAY_MAX", "1500"))    # 延迟超过多少毫秒淘汰
SPEED_TOP = int(os.getenv("SPEED_TOP", "60"))      # 进入测速的数量
MIN_SPEED = float(os.getenv("MIN_SPEED", "1.0"))   # 最低下载速度 MB/s
SPEED_CAP = float(os.getenv("SPEED_CAP", "30"))    # 速度超过这个数不再加分（美国机房测的高速对国内没意义）
KEEP = int(os.getenv("KEEP", "30"))                # 最终保留多少个
CAP_CRED = int(os.getenv("CAP_CRED", "3"))         # 同一 UUID/密码 最多留几个
CAP_NET = int(os.getenv("CAP_NET", "3"))           # 同一网段(/24)或同一域名 最多留几个
CAP_ASN = int(os.getenv("CAP_ASN", "3"))           # 同一出口 ASN 最多留几个
CAP_CC = int(os.getenv("CAP_CC", "12"))            # 同一出口国家最多留几个
PREFER_CC = set(os.getenv("PREFER_CC", "HK,JP,SG,TW,KR").split(","))  # 离国内近，排序加 30%
REQUIRE_GOOGLE = os.getenv("REQUIRE_GOOGLE", "1") == "1"
DEADLINE = int(os.getenv("DEADLINE", "1500"))      # 总耗时超过这么多秒就不再测速
HIST_DAYS = 3
API, MIXED = "http://127.0.0.1:19090", 17890
PROXY = "http://127.0.0.1:%d" % MIXED
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
    if "githubusercontent" in url and len(parts) > 5:
        return "%s/%s" % (parts[3], parts[4])
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


def hkey(k):
    return hashlib.sha1("|".join(map(str, k)).encode()).hexdigest()[:16]


def netkey(h):
    h = str(h).lower()
    try:
        ip = ipaddress.ip_address(h)
        if ip.version == 4:
            return ".".join(h.split(".")[:3])
        return str(ipaddress.ip_network(h + "/48", strict=False))
    except ValueError:
        return ".".join(h.split(".")[-2:])


# ---------------- mihomo ----------------
def start_mihomo(items):
    """启动 mihomo；若因个别节点配置不合法而失败，按报错序号剔除后重试。"""
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
            ys = [it for it in items if it["y"]]
            if not ys:
                raise SystemExit("mihomo 无法启动")
            items = [it for it in items if not it["y"]]  # 保险：丢弃全部 yaml 来源节点再试
    raise SystemExit("mihomo 无法启动")


def delay(name):
    try:
        u = "%s/proxies/%s/delay?url=http%%3A%%2F%%2Fwww.gstatic.com%%2Fgenerate_204&timeout=5000" % (
            API, urllib.parse.quote(name))
        return json.loads(urllib.request.urlopen(u, timeout=10).read())["delay"]
    except Exception:
        return None


def select(name):
    req = urllib.request.Request(API + "/proxies/SEL", data=json.dumps({"name": name}).encode(), method="PUT")
    urllib.request.urlopen(req, timeout=10).read()


def curl(args, t=8):
    r = subprocess.run(["curl", "-s", "-m", str(t), "-x", PROXY] + args, capture_output=True, text=True)
    return r.stdout.strip()


def speed():
    try:
        out = curl(["-o", "/dev/null", "-w", "%{speed_download}",
                    "https://speed.cloudflare.com/__down?bytes=30000000"], 10)
        return float(out or 0) / 1048576
    except Exception:
        return 0.0


def code(url):
    return curl(["-o", "/dev/null", "-w", "%{http_code}", url])


def exit_info():
    try:
        j = json.loads(curl(["http://ip-api.com/json?fields=status,countryCode,as"]))
        if j.get("status") == "success":
            return j.get("countryCode") or "XX", (j.get("as") or "?").split()[0]
    except Exception:
        pass
    return "XX", "?"


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


def load_json(path, default):
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:
        return default


def pick(cands, n):
    """按分数从高到低挑，同时限制同凭据/同网段/同ASN/同国家的数量。"""
    cnt, out = Counter(), []
    for it in cands:
        ks = [("c", cred(it["p"])), ("n", netkey(it["p"]["server"]))]
        if it["asn"] != "?":
            ks.append(("a", it["asn"]))
        if it["cc"] != "XX":
            ks.append(("g", it["cc"]))
        caps = {"c": CAP_CRED, "n": CAP_NET, "a": CAP_ASN, "g": CAP_CC}
        if any(cnt[k] >= caps[k[0]] for k in ks):
            continue
        for k in ks:
            cnt[k] += 1
        out.append(it)
        if len(out) >= n:
            break
    return out


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
        items.append({"p": p, "src": src, "y": isy, "k": k, "h": hkey(k), "prior": prior})
        return True

    # 上一次入选的节点先放进来：必复测，保证"可持续"的节点不会被随机抽样漏掉
    for p in (load_json_yaml(os.path.join(HERE, "free.yaml")) or []):
        add(p, -1, True, True)
    n_prior = len(items)

    with ThreadPoolExecutor(8) as ex:
        results = list(ex.map(fetch, urls))
    for idx, (url, got, err) in enumerate(results):
        new = sum(1 for p, isy in got if add(p, idx, isy))
        stat.append((label(url), len(got), new, err))
        print("%-40s 解析%-6d 新增%-6d %s" % (label(url), len(got), new, ("失败:" + err) if err else ""))

    # 各来源均衡抽样，避免被某一个超大来源淹没
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
    print("候选节点 %d（其中上次入选 %d）" % (total, n_prior))
    if total == 0:
        notify("⚠️ 免费节点更新：所有来源都没抓到节点")
        raise SystemExit(0)

    hist = load_json(os.path.join(HERE, "history.json"), {})
    now = int(time.time())
    proc, sel = start_mihomo(sel)
    alive, res, drops = [], [], Counter()
    try:
        with ThreadPoolExecutor(48) as ex:
            ds = list(ex.map(delay, [it["p"]["name"] for it in sel]))
        for d, it in zip(ds, sel):
            it["d"] = d
            if d and d <= DELAY_MAX:
                alive.append(it)
        print("延迟合格", len(alive))

        # 进入测速的名单：上次入选的优先，再按延迟排，同时对同凭据/同网段先限 2 个
        cnt, pool = Counter(), []
        for it in sorted(alive, key=lambda x: (0 if x["prior"] else 1, x["d"])):
            kc, kn = ("c", cred(it["p"])), ("n", netkey(it["p"]["server"]))
            if cnt[kc] >= 2 or cnt[kn] >= 2:
                continue
            cnt[kc] += 1
            cnt[kn] += 1
            pool.append(it)
            if len(pool) >= SPEED_TOP:
                break

        for it in pool:
            if time.time() - T0 > DEADLINE:
                print("超时，停止测速")
                break
            try:
                select(it["p"]["name"])
            except Exception:
                continue
            s = speed()
            it["s"] = s
            if s < MIN_SPEED:
                drops["速度不足"] += 1
                continue
            g = code("https://www.google.com/generate_204") == "204"
            if REQUIRE_GOOGLE and not g:
                drops["Google不通"] += 1
                continue
            tg = code("https://api.telegram.org") in ("200", "301", "302", "404")
            ai = code("https://api.openai.com/v1/models") == "401"
            it["cc"], it["asn"] = exit_info()
            it["tags"] = ("G" if g else "") + ("T" if tg else "") + ("A" if ai else "")
            print(it["p"]["name"], it["d"], "ms", round(s, 1), "MB/s", it["cc"], it["asn"], it["tags"])
            res.append(it)
    finally:
        proc.kill()

    # 更新稳定性历史：这次延迟合格的 +1，测了但没通过的清掉，3 天没出现的清理
    alive_h = {it["h"] for it in alive}
    for it in sel:
        if it["h"] in alive_h:
            hist[it["h"]] = {"n": hist.get(it["h"], {}).get("n", 0) + 1, "t": now}
        else:
            hist.pop(it["h"], None)
    hist = {k: v for k, v in hist.items() if v.get("t", 0) > now - HIST_DAYS * 86400}
    json.dump(hist, open(os.path.join(HERE, "history.json"), "w"))

    for it in res:
        it["n"] = hist.get(it["h"], {}).get("n", 1)
        it["score"] = (min(it["s"], SPEED_CAP) * (1 + 0.1 * min(it["n"], 10))
                       * (1.3 if it["cc"] in PREFER_CC else 1.0))
    res.sort(key=lambda x: -x["score"])
    final = pick(res, KEEP)

    bj = time.strftime("%Y-%m-%d %H:%M", time.gmtime(now + 8 * 3600))
    rep = ["# 更新报告", "", "北京时间: " + bj, "",
           "候选 %d（上次入选 %d）→ 延迟合格 %d → 进入测速 %d → 测速/连通合格 %d → 去重后保留 %d" % (
               total, n_prior, len(alive), len(pool), len(res), len(final)),
           "淘汰原因：" + ("，".join("%s %d" % kv for kv in drops.items()) or "无"), "", "## 来源"]
    rep += ["- %s：解析 %d，新增 %d %s" % (a, b, c, ("❌" + e) if e else "") for a, b, c, e in stat]
    rep += ["", "## 入选节点", "", "| # | 国家 | 速度MB/s | 延迟ms | 连续合格 | 标记 | 协议 |", "|---|---|---|---|---|---|---|"]
    for i, it in enumerate(final, 1):
        rep.append("| %d | %s | %.1f | %d | %d | %s | %s |" % (i, it["cc"], it["s"], it["d"], it["n"],
                                                              it["tags"], it["p"]["type"]))
    rep += ["", "标记：G=Google可达 T=Telegram可达 A=OpenAI接口可达。连续合格=已连续多少次更新都存活。"]
    open(os.path.join(HERE, "report.md"), "w", encoding="utf-8").write("\n".join(rep) + "\n")

    dead_src = [a for a, b, c, e in stat if e]
    if len(final) < 3:
        notify("⚠️ 免费节点更新：合格节点只有 %d 个，保留上一次结果。失效来源：%s" % (len(final), "、".join(dead_src) or "无"))
        return
    out = []
    for i, it in enumerate(final, 1):
        p = dict(it["p"])
        p["name"] = "免费%02d-%s-%.0fM-%dms-%s%s" % (i, it["cc"], it["s"], it["d"], it["tags"],
                                                    ("-稳%d" % it["n"]) if it["n"] >= 3 else "")
        out.append(p)
    with open(os.path.join(HERE, "free.yaml"), "w", encoding="utf-8") as f:
        yaml.dump({"proxies": out}, f, Dumper=NoAlias, allow_unicode=True, sort_keys=False)
    ccs = Counter(it["cc"] for it in final)
    stable = sum(1 for it in final if it["n"] >= 3)
    notify("✅ 免费节点已更新（北京 %s）\n候选%d → 保留%d 个，其中连续稳定≥3次的 %d 个\n最快 %.1f MB/s\n国家：%s%s" % (
        bj, total, len(final), stable, final[0]["s"],
        " ".join("%s%d" % kv for kv in ccs.most_common(6)),
        ("\n失效来源：" + "、".join(dead_src)) if dead_src else ""))


def load_json_yaml(path):
    try:
        d = yaml.safe_load(open(path, encoding="utf-8"))
        return [p for p in d["proxies"] if isinstance(p, dict)]
    except Exception:
        return []


if __name__ == "__main__":
    main()
