#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
suzhou.py —— 在你的路由器（苏州电信线路）上实测 GitHub 产出的候选池 pool.yaml，
只留下"在你家真的能用"的节点，生成可订阅的 free.yaml / full.yaml。

用法（都在路由器 SSH 里）：
  python3 suzhou.py --install     安装：开机自启 + 每小时 50 分按时段运行 + 本机订阅服务
  python3 suzhou.py --now         马上完整跑一次
  python3 suzhou.py --report      看最近一次结果
  python3 suzhou.py --uninstall   卸载
"""
import os, re, sys, json, time, socket, subprocess, hashlib, ipaddress, urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
try:
    import fcntl
except ImportError:
    fcntl = None
try:
    import yaml
except ImportError:
    yaml = None

REPO = "xiaoyanyan753-blip/freenodes"
POOL_URL = "https://raw.githubusercontent.com/%s/main/pool.yaml" % REPO
CLASH_PROXY = "http://127.0.0.1:23456"          # 你的 Merlin Clash 混合端口，只用来拉候选池和发通知
PORT = int(os.getenv("FN_PORT", "8099"))
BIND = os.getenv("FN_BIND", "127.0.0.1")
CORE_CANDS = ["/koolshare/bin/clash", "/jffs/.koolshare/bin/clash"]
PY = "/opt/bin/python3"
MP = "/tmp/mnt/KSDISK"
BASE = os.path.dirname(os.path.abspath(__file__))
WWW, LOGD, STATE = BASE + "/www", BASE + "/logs", BASE + "/state.json"
WORK, CTRL, P0 = "/tmp/fn_mh", "127.0.0.1:19091", 21000

QUOTA = [("SG", 2), ("JP", 3), ("TW", 2), ("US", 5), ("HK", 2), ("GB", 1), ("DE", 1)]
NAME = {"SG": "新加坡", "JP": "日本", "TW": "台湾", "US": "美国", "HK": "香港", "GB": "英国", "DE": "德国"}
NO_AI = {"HK"}                                    # 香港出口通常不被 ChatGPT/Gemini 支持，只要求 YouTube+GitHub
KEEP = int(os.getenv("KEEP", "30"))
EXTRA_CAP = int(os.getenv("EXTRA_CAP", "6"))      # 凑满 KEEP 时，每个国家在配额之外最多再多留几个
LAT_MAX = int(os.getenv("LAT_MAX", "2500"))       # 毫秒，三次 HTTPS 请求的平均耗时上限
THREADS = int(os.getenv("THREADS", "8"))
MIN_SPEED = float(os.getenv("MIN_SPEED", "0.3"))  # MB/s（0.3≈2.4Mbps，聊天类 AI 够用；想更严就调高）
SPEED_CAP, SPEED_TTL, SPEED_PER_CC = 20.0, 6 * 3600, 10
MAX_NODES = int(os.getenv("MAX_NODES", "2400"))
BATCH = int(os.getenv("BATCH", "400"))            # 每批同时开多少个节点（内存友好）
PRE_THREADS = int(os.getenv("PRE_THREADS", "16"))
SPEED_PER_BATCH = 25                              # 每批最多测速几个
SCHED_HOURS = {20, 21, 22, 23, 0, 2, 8, 14}       # 北京时间


def log(*a):
    s = time.strftime("%m-%d %H:%M:%S", time.gmtime(time.time() + 8 * 3600)) + " " + " ".join(map(str, a))
    print(s, flush=True)
    try:
        os.makedirs(LOGD, exist_ok=True)
        f = LOGD + "/fn.log"
        if os.path.exists(f) and os.path.getsize(f) > 400 * 1024:
            os.replace(f, f + ".1")
        open(f, "a", encoding="utf-8").write(s + "\n")
    except OSError:
        pass


# ---------------- 通用 ----------------
def cred(p):
    return str(p.get("uuid") or p.get("password") or "")


def key(p):
    return (p["type"], str(p["server"]).lower(), int(p["port"]), cred(p))


def hkey(p):
    return hashlib.sha1("|".join(map(str, key(p))).encode()).hexdigest()[:16]


def netkey(h):
    h = str(h).lower()
    try:
        ip = ipaddress.ip_address(h)
        if ip.version == 4:
            return ".".join(h.split(".")[:3])
        return str(ipaddress.ip_network(h + "/48", strict=False))
    except ValueError:
        return ".".join(h.split(".")[-2:])


def load_state():
    try:
        return json.load(open(STATE, encoding="utf-8"))
    except Exception:
        return {"hist": {}, "speed": {}, "last": []}


def sh(cmd, inp=None, t=60):
    return subprocess.run(cmd, input=inp, capture_output=True, text=True, timeout=t)


def fetch_pool():
    for px in (None, CLASH_PROXY):
        cmd = ["curl", "-sSL", "-m", "40", POOL_URL]
        if px:
            cmd[1:1] = ["-x", px]
        try:
            d = yaml.safe_load(sh(cmd).stdout)
            lst = [p for p in d["proxies"] if isinstance(p, dict)]
            if lst:
                log("候选池 %d 个（%s）" % (len(lst), "直连" if not px else "经代理"))
                return lst
        except Exception:
            pass
    raise SystemExit("拉不到候选池 pool.yaml：先确认 GitHub 那边已经成功运行过一次")


def fetch_local():
    """读取 U 盘上的私有订阅清单 my_sources.txt（只在路由器本地，不进 GitHub）。"""
    f = BASE + "/my_sources.txt"
    out = []
    if not os.path.exists(f):
        return out
    sys.path.insert(0, BASE)
    try:
        import collect
    except Exception as e:
        log("读取私有订阅需要同目录的 collect.py（%s）" % e)
        return out
    for line in open(f, encoding="utf-8-sig").read().splitlines():
        u = line.strip()
        if not u or u.startswith("#"):
            continue
        got = []
        for px in (None, CLASH_PROXY):
            cmd = ["curl", "-sSL", "-m", "40", "-A", "clash.meta", u]
            if px:
                cmd[1:1] = ["-x", px]
            try:
                txt = sh(cmd).stdout
                got = collect.from_text(txt)
                if not got:
                    d = yaml.safe_load(txt)
                    if isinstance(d, dict) and isinstance(d.get("proxies"), list):
                        got = [(p, True) for p in d["proxies"] if isinstance(p, dict) and p.get("server")
                               and p.get("port") and p.get("type")]
            except Exception:
                got = []
            if got:
                break
        host = u.split("/")[2] if u.count("/") > 2 else "?"
        log("私有来源 %s：%d 个节点" % (host, len(got)))
        out += [dict(p, name="MY-%d" % len(out)) for p, _ in got]
    return out


# ---------------- 内核：每个候选节点一个独立监听端口，可并行实测 ----------------
def wan_iface():
    """物理出口网卡（你的是 ppp0）。核心的所有外发连接绑定到它，绕开 Merlin Clash 对路由器本机流量的接管。"""
    if os.getenv("FN_IFACE"):
        return os.getenv("FN_IFACE")
    try:
        v = sh(["nvram", "get", "wan0_gw_ifname"]).stdout.strip()
        if v:
            return v
        m = re.search(r"default via \S+ dev (\S+)", sh(["ip", "route"]).stdout)
        return m.group(1) if m else None
    except Exception:
        return None


def start_core(items):
    core = next((c for c in CORE_CANDS if os.path.exists(c)), None)
    if not core:
        raise SystemExit("找不到 clash 内核（/koolshare/bin/clash）")
    os.makedirs(WORK, exist_ok=True)
    WAN = wan_iface()
    log("外发网卡绑定：%s" % (WAN or "未指定"))
    for _ in range(60):
        for i, it in enumerate(items):
            it["p"]["name"] = "n%d" % i
        cfg = {"external-controller": CTRL, "log-level": "info", "mode": "rule", "ipv6": False,
               "routing-mark": 256,          # 0x100：Merlin Clash 的防火墙规则对带这个标记的连接直接放行
               **({"interface-name": WAN} if WAN else {}),
               "dns": {"enable": True, "nameserver": ["223.5.5.5", "119.29.29.29"],
                       "default-nameserver": ["223.5.5.5", "119.29.29.29"]},
               "proxies": [it["p"] for it in items],
               "listeners": [{"name": "direct", "type": "mixed", "port": P0 - 1, "listen": "127.0.0.1",
                              "proxy": "DIRECT"}] +
                            [{"name": "l%d" % i, "type": "mixed", "port": P0 + i, "listen": "127.0.0.1",
                              "proxy": it["p"]["name"]} for i, it in enumerate(items)],
               "rules": ["MATCH,DIRECT"]}
        with open(WORK + "/config.yaml", "w") as f:
            yaml.safe_dump(cfg, f, allow_unicode=True)
        lf = open(WORK + "/log.txt", "w")
        proc = subprocess.Popen([core, "-d", WORK, "-f", WORK + "/config.yaml"], stdout=lf, stderr=lf)
        for _ in range(40):
            time.sleep(1)
            try:
                urllib.request.urlopen("http://%s/version" % CTRL, timeout=2).read()
                return proc, items
            except Exception:
                if proc.poll() is not None:
                    break
        proc.kill()
        txt = open(WORK + "/log.txt", errors="ignore").read()
        log("内核启动失败：", txt[-300:].replace("\n", " | "))
        m = re.search(r"proxy (\d+)", txt)
        if m and int(m.group(1)) < len(items):
            del items[int(m.group(1))]
        else:
            raise SystemExit("内核无法启动，请把上面的日志发给我")
    raise SystemExit("内核无法启动")


def cur(port, url, t=8):
    """通过某个监听端口访问 url，返回 (状态码, 响应体, 耗时秒)。"""
    try:
        r = sh(["curl", "-s", "-m", str(t), "-x", "http://127.0.0.1:%d" % port, "-o", "-", "-w",
                "\n%{http_code} %{time_total}", url], t=t + 5)
        body, _, tail = r.stdout.rpartition("\n")
        code, tm = tail.split()
        return code, body, float(tm)
    except Exception:
        return "000", "", 0.0


def selftest():
    """确认监听功能可用，并确认路由器自己的直连出口确实在大陆（否则实测结果不代表苏州线路）。"""
    c, b, _ = cur(P0 - 1, "https://www.cloudflare.com/cdn-cgi/trace", 10)
    m = re.search(r"loc=(\w+)", b)
    loc = m.group(1) if m else None
    if c != "200":
        raise SystemExit("自检失败：内核的监听端口不通。可能内核版本不支持 listeners，请把 `/koolshare/bin/clash -v` 的输出发给我")
    if loc != "CN":
        raise SystemExit("自检失败：路由器自己的直连出口显示在 %s，不是大陆。说明路由器本机流量被代理接管，"
                         "此时实测结果不代表苏州线路，已停止。请把日志发给我。" % loc)
    log("自检通过：直连出口 CN，监听功能正常")


# ---------------- 单个节点的实测 ----------------
def probe(it):
    port, p = P0 + it["i"], it["p"]
    ts, loc, fails = [], None, 0
    for _ in range(3):
        c, b, t = cur(port, "https://www.cloudflare.com/cdn-cgi/trace", 6)
        if c == "200":
            ts.append(t)
            m = re.search(r"loc=(\w+)", b)
            loc = loc or (m.group(1) if m else None)
        else:
            fails += 1
            if fails >= 2:
                return dict(ok=False, why="连不上")
    lat = int(sum(ts) / len(ts) * 1000)
    if lat > LAT_MAX:
        return dict(ok=False, why="延迟过高")
    cc = loc or it["cc0"]
    if not re.fullmatch(r"[A-Z]{2}", str(cc)) or cc == "XX":
        return dict(ok=False, why="无法确定出口国家")
    if cur(port, "https://www.youtube.com/generate_204")[0] != "204":
        return dict(ok=False, why="YouTube不通")
    if cur(port, "https://api.github.com")[0] != "200":
        return dict(ok=False, why="GitHub不通")
    ai = False
    if cc not in NO_AI:
        oa = cur(port, "https://api.openai.com/v1/models")[0] == "401"
        if not oa:
            return dict(ok=False, why="OpenAI不通")
        c, b, _ = cur(port, "https://api.anthropic.com/v1/models")
        if c not in ("401", "400", "404", "405"):
            return dict(ok=False, why="Claude不通")
        c, b, _ = cur(port, "https://generativelanguage.googleapis.com/v1beta/models")
        if c not in ("403", "401") or "location is not supported" in b.lower():
            return dict(ok=False, why="Gemini不通")
        ai = True
    return dict(ok=True, cc=cc, lat=lat, ai=ai)


SPEED_URLS = ["https://speed.cloudflare.com/__down?bytes=20000000", "http://cachefly.cachefly.net/50mb.test"]


def speed(port):
    best = 0.0
    for u in SPEED_URLS:
        try:
            r = sh(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{speed_download}", "-m", "8", "-x",
                    "http://127.0.0.1:%d" % port, u], t=15)
            code, spd = r.stdout.split()[:2]
            if code == "200":
                best = max(best, float(spd) / 1048576)
                if best >= MIN_SPEED:
                    break
        except Exception:
            pass
    return best


# ---------------- 挑选与输出 ----------------
def pick(cands, n, cnt):
    out = []
    for it in cands:
        if len(out) >= n:
            break
        kc, kn = ("c", cred(it["p"])), ("n", netkey(it["p"]["server"]))
        if cnt[kc] >= 2 or cnt[kn] >= 2:
            continue
        cnt[kc] += 1
        cnt[kn] += 1
        out.append(it)
    return out


def choose(oks):
    cnt, final, gaps = Counter(), [], {}
    quota = dict(QUOTA)
    for cc, q in QUOTA:
        got = pick(sorted([x for x in oks if x["cc"] == cc], key=lambda x: -x["score"]), q, cnt)
        final += got
        if len(got) < q:
            gaps[cc] = q - len(got)
    taken = {id(x) for x in final}
    per = Counter(x["cc"] for x in final)
    for it in sorted([x for x in oks if id(x) not in taken], key=lambda x: -x["score"]):
        if len(final) >= KEEP:
            break
        if per[it["cc"]] >= quota.get(it["cc"], 0) + EXTRA_CAP:
            continue
        if pick([it], 1, cnt):
            final.append(it)
            per[it["cc"]] += 1
    return final, gaps


def build_full(final):
    names = [x["p"]["name"] for x in final]
    by = {cc: [x["p"]["name"] for x in final if x["cc"] == cc] for cc in NAME}
    cg = ["免费-" + NAME[cc] for cc, _ in QUOTA if by[cc]]

    def ut(n, ps):
        return {"name": n, "type": "url-test", "proxies": ps, "url": "https://www.gstatic.com/generate_204",
                "interval": 600, "tolerance": 80, "lazy": True}
    ai = [x["p"]["name"] for x in final if x["ai"]] or names
    groups = [{"name": "免费-选择", "type": "select", "proxies": ["免费-自动"] + cg + ["DIRECT"]},
              ut("免费-自动", names)]
    groups += [ut("免费-" + NAME[cc], by[cc]) for cc, _ in QUOTA if by[cc]]
    groups += [ut("免费-AI", ai),
               {"name": "免费-YouTube", "type": "select", "proxies": ["免费-自动"] + cg},
               {"name": "免费-GitHub", "type": "select", "proxies": ["免费-自动"] + cg + ["DIRECT"]}]

    def dom(g, lst):
        return ["DOMAIN-SUFFIX,%s,%s" % (d, g) for d in lst]
    rules = (dom("免费-AI", ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "anthropic.com",
                           "claude.ai", "claude.com", "gemini.google.com", "aistudio.google.com",
                           "generativelanguage.googleapis.com", "perplexity.ai", "grok.com", "x.ai"]) +
             dom("免费-YouTube", ["youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com",
                                 "youtube-nocookie.com"]) +
             dom("免费-GitHub", ["github.com", "githubusercontent.com", "githubassets.com", "github.io",
                                "githubapp.com", "ghcr.io"]) +
             ["GEOIP,LAN,DIRECT,no-resolve", "GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT,no-resolve",
              "MATCH,免费-选择"])
    return {"proxies": [x["p"] for x in final], "proxy-groups": groups, "rules": rules}


class NoAlias(yaml.SafeDumper if yaml else object):
    def ignore_aliases(self, data):
        return True


def write_if_changed(path, text):
    try:
        if open(path, encoding="utf-8").read() == text:
            return
    except OSError:
        pass
    open(path + ".tmp", "w", encoding="utf-8").write(text)
    os.replace(path + ".tmp", path)


def notify(text):
    try:
        tok = chat = None
        for l in open(MP + "/tgbots/bots.conf", encoding="utf-8-sig").read().splitlines():
            l = l.strip()
            if not l or l.startswith("#") or re.match(r"^[A-Z_]+\s*=", l):
                continue
            parts = l.split()
            tok, chat = parts[0], re.split(r"[,;，；]", parts[1])[0]
            break
        if not tok:
            return
        esc = text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        cfg = 'url = "https://api.telegram.org/bot%s/sendMessage"\nproxy = "%s"\ndata = "chat_id=%s"\n' \
              'data-urlencode = "text=%s"\n' % (tok, CLASH_PROXY, chat, esc)
        sh(["curl", "-s", "-m", "20", "-K", "-"], inp=cfg)
    except Exception:
        pass


# ---------------- 主流程 ----------------
def mask(t):
    t = re.sub(r"\d+\.\d+\.\d+\.\d+(:\d+)?", "x", t)
    return re.sub(r"[\w.-]+:\d+", "H", t)[:80]


def private_reasons(bad):
    """私有来源节点初筛失败时，从内核日志里提取真实原因（已打码，不含域名和IP）。"""
    why = Counter()
    try:
        lines = open(WORK + "/log.txt", errors="ignore").read().splitlines()
    except OSError:
        lines = []
    last = {}
    for ln in lines:
        m = re.search(r"dial n(\d+) .*? error: (.*)$", ln)
        if m:
            last[int(m.group(1))] = m.group(2).rstrip('"')
    for it in bad:
        why[mask(last.get(it["i"], "内核日志里没有记录（可能被对方当网页应答或协议不支持）"))] += 1
    return why


def prefilter(it):
    """严格的初筛：必须真的拿到 204（只返回一个网页的假节点会被挡掉）。"""
    return cur(P0 + it["i"], "http://www.gstatic.com/generate_204", 5)[0] == "204"


def run():
    lock = None
    if fcntl:
        lock = open("/tmp/fn.lock", "w")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            log("上一轮还在跑，跳过")
            return
    t0 = time.time()
    st = load_state()
    now = int(time.time())
    seen, items = set(), []
    local = fetch_local()
    priv_k = set()
    for p in local:
        try:
            priv_k.add(key(dict(p, port=int(p["port"]))))
        except Exception:
            pass
    for p in st.get("last", []) + local + fetch_pool():   # 上次入选的、私有订阅的先放前面
        try:
            p = dict(p)
            p["port"] = int(p["port"])
            k = key(p)
        except Exception:
            continue
        if k in seen:
            continue
        seen.add(k)
        cc0 = (str(p.get("name", "")).split("-")[0] or "XX").upper()
        items.append({"p": p, "h": hkey(p), "cc0": cc0, "i": 0, "src": "private" if k in priv_k else "pool"})
    items = items[:MAX_NODES]
    log("本轮实测 %d 个节点，每批 %d 个" % (len(items), BATCH))
    spd = st.setdefault("speed", {})
    drops, oks, tested, lows = Counter(), [], [], []
    n_pre = n_good = 0
    S = {k: Counter() for k in ("n", "pre", "good", "ok")}
    priv_why = Counter()
    for b in range(0, len(items), BATCH):
        batch = items[b:b + BATCH]
        proc, batch = start_core(batch)
        for i, it in enumerate(batch):
            it["i"] = i
        try:
            if b == 0:
                selftest()
            with ThreadPoolExecutor(PRE_THREADS) as ex:
                pre = list(ex.map(prefilter, batch))
            alive = [it for it, ok in zip(batch, pre) if ok]
            for it, ok in zip(batch, pre):
                S["n"][it["src"]] += 1
                S["pre"][it["src"]] += 1 if ok else 0
            bad_priv = [it for it, ok in zip(batch, pre) if not ok and it["src"] == "private"]
            if bad_priv:
                with ThreadPoolExecutor(8) as ex:
                    list(ex.map(lambda x: cur(P0 + x["i"], "http://www.gstatic.com/generate_204", 8), bad_priv))
                priv_why.update(private_reasons(bad_priv))
            drops["基础不通"] += len(batch) - len(alive)
            n_pre += len(alive)
            with ThreadPoolExecutor(THREADS) as ex:
                res = list(ex.map(probe, alive))
            good = []
            for it, r in zip(alive, res):
                if r["ok"]:
                    it.update(r)
                    good.append(it)
                else:
                    drops[r["why"]] += 1
            n_good += len(good)
            for it in good:
                S["good"][it["src"]] += 1
            good.sort(key=lambda x: x["lat"])
            drops["超出测速名额"] += max(0, len(good) - SPEED_PER_BATCH)
            for it in good[:SPEED_PER_BATCH]:
                c = spd.get(it["h"])
                if c and now - c[1] < SPEED_TTL:
                    sp = c[0]
                else:
                    sp = speed(P0 + it["i"])
                    spd[it["h"]] = [sp, now]
                log("  %s %s %dms %.2fMB/s %s" % (it["cc"], it["p"]["type"], it["lat"], sp,
                                                  "AI" if it["ai"] else "非AI"))
                if sp < MIN_SPEED:
                    drops["速度不足"] += 1
                    lows.append((it["cc"], it["lat"], sp, it["p"]["type"]))
                    continue
                it["s"] = sp
                S["ok"][it["src"]] += 1
                oks.append(it)
            log("第 %d 批：%d 个 → 初筛通过 %d → 完整检测合格 %d；累计入围 %d" % (
                b // BATCH + 1, len(batch), len(alive), len(good), len(oks)))
        finally:
            proc.kill()
            try:
                proc.wait(5)
            except Exception:
                pass
        tested += batch

    hist = st.setdefault("hist", {})
    okh = {it["h"] for it in oks}
    for it in tested:
        if it["h"] in okh:
            hist[it["h"]] = {"n": hist.get(it["h"], {}).get("n", 0) + 1, "t": now}
        else:
            hist.pop(it["h"], None)
    st["hist"] = {k: v for k, v in hist.items() if v["t"] > now - 3 * 86400}
    st["speed"] = {k: v for k, v in spd.items() if now - v[1] < 3 * 86400}
    for it in oks:
        it["n"] = st["hist"].get(it["h"], {}).get("n", 1)
        it["score"] = min(it["s"], SPEED_CAP) / (1 + it["lat"] / 300.0) * (1 + 0.1 * min(it["n"], 10))
    final, gaps = choose(oks)
    bj = time.strftime("%Y-%m-%d %H:%M", time.gmtime(now + 8 * 3600))
    cnt = Counter(x["cc"] for x in final)
    lines = ["苏州线路实测报告  北京时间 " + bj, "",
             "候选 %d → 初筛通过 %d → 完整检测合格 %d → 速度合格 %d → 入选 %d" % (
                 len(tested), n_pre, n_good, len(oks), len(final)),
             "淘汰原因：" + "，".join("%s %d" % kv for kv in drops.items()),
             "各国入选：" + "，".join("%s %d" % (NAME[c], cnt[c]) for c, _ in QUOTA)]
    if S["n"]["private"]:
        lines.append("私有来源节点 %d 个：初筛通过 %d → 完整合格 %d → 速度合格 %d" % (
            S["n"]["private"], S["pre"]["private"], S["good"]["private"], S["ok"]["private"]))
        if priv_why:
            lines.append("私有节点初筛失败原因：" + "；".join("%s×%d" % kv for kv in priv_why.most_common(6)))
    others = Counter(x["cc"] for x in final if x["cc"] not in NAME)
    if others:
        lines.append("其他国家入选：" + "，".join("%s %d" % kv for kv in others.items()))
    if gaps:
        lines.append("⚠️ 配额缺口：" + "，".join("%s 缺 %d" % (NAME[c], n) for c, n in gaps.items()))
    if lows:
        lines += ["", "# 能通但速度未达标(<%.1f MB/s)的节点" % MIN_SPEED] + [
            "%s  %d ms  %.2f MB/s  %s" % (c, l, sp, t) for c, l, sp, t in sorted(lows, key=lambda x: -x[2])[:15]]
    os.makedirs(WWW, exist_ok=True)
    write_if_changed(WWW + "/report.txt", "\n".join(lines) + "\n")
    if not final or (len(final) < 3 and os.path.exists(WWW + "/free.yaml")):
        log("入选太少，保留上一次的订阅文件。\n" + "\n".join(lines))
        notify("⚠️ 免费节点更新：\n" + "\n".join(lines))
        json.dump(st, open(STATE, "w"))
        return
    order = {cc: i for i, (cc, _) in enumerate(QUOTA)}
    final.sort(key=lambda x: (order.get(x["cc"], 99), -x["score"]))
    seq = Counter()
    for it in final:
        seq[it["cc"]] += 1
        it["p"]["name"] = "免费-%s%02d-%.1fM-%dms-%s" % (it["cc"], seq[it["cc"]], it["s"], it["lat"],
                                                        "AI" if it["ai"] else "非AI")
    lines += ["", "# 入选节点"] + ["%s  %.1f MB/s  %d ms  连续合格%d次  %s" % (
        it["p"]["name"], it["s"], it["lat"], it["n"], it["p"]["type"]) for it in final]
    os.makedirs(WWW, exist_ok=True)
    dump = lambda d: yaml.dump(d, Dumper=NoAlias, allow_unicode=True, sort_keys=False)
    write_if_changed(WWW + "/free.yaml", dump({"proxies": [x["p"] for x in final]}))
    write_if_changed(WWW + "/full.yaml", dump(build_full(final)))
    write_if_changed(WWW + "/report.txt", "\n".join(lines) + "\n")
    st["last"] = [dict(x["p"], name=x["cc"] + "-last") for x in final]
    json.dump(st, open(STATE, "w"))
    log("完成：入选 %d 个，用时 %d 秒" % (len(final), time.time() - t0))
    notify("✅ 苏州线路实测完成（北京 %s）\n入选 %d 个：%s\n最快 %.1f MB/s%s" % (
        bj, len(final), " ".join("%s%d" % (NAME[c], cnt[c]) for c, _ in QUOTA if cnt[c]),
        max(x["s"] for x in final), ("\n⚠️ 缺口：" + "，".join("%s缺%d" % (NAME[c], n) for c, n in gaps.items()))
        if gaps else ""))


# ---------------- 诊断：弄清楚"连不上"到底是节点真的被封，还是测试方法有问题 ----------------
def tcp_try(p, wan):
    """从路由器的物理网卡直接 TCP 连一下节点端口（不经过任何代理）。"""
    try:
        s = socket.socket()
        s.settimeout(4)
        if wan:
            s.setsockopt(socket.SOL_SOCKET, 25, wan.encode() + b"\0")   # SO_BINDTODEVICE
        s.connect((str(p["server"]), int(p["port"])))
        s.close()
        return "ok"
    except Exception as e:
        return re.sub(r"[\d.]{7,}", "x", str(e))[:40]


def api_delay(name):
    import urllib.parse
    u = "http://%s/proxies/%s/delay?url=http%%3A%%2F%%2Fwww.gstatic.com%%2Fgenerate_204&timeout=6000" % (
        CTRL, urllib.parse.quote(name))
    try:
        json.loads(urllib.request.urlopen(u, timeout=12).read())
        return "ok"
    except Exception as e:
        try:
            return re.sub(r"[\d.]{7,}", "x", json.loads(e.read().decode()).get("message", str(e)))[:60]
        except Exception:
            return re.sub(r"[\d.]{7,}", "x", str(e))[:60]


def cur_dbg(port, url, t=12):
    """和 cur 一样，但把 curl 的退出码和错误信息也带回来（诊断用）。"""
    try:
        r = sh(["curl", "-sS", "-m", str(t), "-x", "http://127.0.0.1:%d" % port, "-o", "/dev/null", "-w",
                "%{http_code} %{time_total}", url], t=t + 5)
        code, tm = (r.stdout.strip().split() + ["0", "0"])[:2]
        err = re.sub(r"\d{2,}", "N", (r.stderr.strip().splitlines() or [""])[-1])[:70]
        return code, r.returncode, float(tm), err
    except Exception as e:
        return "000", -1, 0.0, str(e)[:50]


def diag():
    import random
    wan = wan_iface()
    pool = [p for p in fetch_pool() if p.get("type") != "hysteria2"]
    random.shuffle(pool)
    pool = pool[:60]
    items = [{"p": dict(p), "i": i} for i, p in enumerate(pool)]
    log("诊断 %d 个节点，网卡 %s" % (len(items), wan))
    with ThreadPoolExecutor(30) as ex:
        tcp = list(ex.map(lambda it: tcp_try(it["p"], wan), items))
    proc, items = start_core(items)
    try:
        selftest()
        with ThreadPoolExecutor(THREADS) as ex:
            api = list(ex.map(lambda it: api_delay(it["p"]["name"]), items))
            https = list(ex.map(lambda it: cur_dbg(P0 + it["i"], "https://www.cloudflare.com/cdn-cgi/trace"), items))
            http_ = list(ex.map(lambda it: cur_dbg(P0 + it["i"], "http://www.gstatic.com/generate_204"), items))
    finally:
        proc.kill()
    print("\nTCP 直连端口：通 %d / %d" % (sum(1 for x in tcp if x == "ok"), len(tcp)))
    print("  失败原因：", dict(Counter(x for x in tcp if x != "ok")))
    print("经内核代理的延迟测试：通 %d / %d" % (sum(1 for x in api if x == "ok"), len(api)))
    print("  失败原因：", dict(Counter(x for x in api if x != "ok")))
    by = Counter()
    for it, t, a in zip(items, tcp, api):
        by[(it["p"]["type"], t == "ok", a == "ok")] += 1
    print("按协议 (类型, TCP通, 代理通)：", dict(by))
    def summ(name, rs):
        okc = [r for r in rs if r[0] in ("200", "204")]
        print("%s：通 %d / %d%s" % (name, len(okc), len(rs), ("，通的平均耗时 %.1fs" % (
            sum(r[2] for r in okc) / len(okc))) if okc else ""))
        print("  失败(curl退出码/信息)：", dict(Counter("状态码%s 退出码%s %s" % (r[0], r[1], r[3]) for r in rs if r[0] not in ("200", "204"))))
    print()
    summ("curl→HTTPS cloudflare", https)
    summ("curl→HTTP gstatic", http_)
    print("交叉：(内核延迟测试通, curl-HTTPS通, curl-HTTP通) →", dict(Counter(
        (a == "ok", h[0] == "200", q[0] == "204") for a, h, q in zip(api, https, http_))))
    print("\n内核日志末尾：")
    print("\n".join(open(WORK + "/log.txt", errors="ignore").read().splitlines()[-12:]))


# ---------------- 安装 / 服务 ----------------
def serve():
    os.makedirs(WWW, exist_ok=True)
    try:
        os.kill(int(open("/tmp/fn_http.pid").read()), 0)
        return
    except Exception:
        pass
    p = subprocess.Popen([PY, "-m", "http.server", str(PORT), "--bind", BIND, "--directory", WWW],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    open("/tmp/fn_http.pid", "w").write(str(p.pid))
    log("本机订阅服务已启动 http://%s:%d/" % (BIND, PORT))


def stop():
    try:
        os.kill(int(open("/tmp/fn_http.pid").read()), 15)
    except Exception:
        pass
    try:
        os.remove("/tmp/fn_http.pid")
    except OSError:
        pass


def install():
    if yaml is None:
        raise SystemExit("缺少 PyYAML，请先执行： /opt/bin/opkg install python3-yaml")
    H = "/koolshare/init.d"
    if not os.path.isdir(H):
        raise SystemExit("找不到 " + H)
    cmd = "%s %s/suzhou.py" % (PY, BASE)
    m = ('#!/bin/sh\n[ "$1" = "%s" ] || exit 0\n(\n  i=0\n  while [ $i -lt 30 ] && [ ! -x %s ]; do sleep 2; i=$((i+1)); done\n'
         '  cru d freenodes 2>/dev/null\n  cru a freenodes "50 * * * * %s --scheduled"\n  %s --serve\n) >/dev/null 2>&1 &\nexit 0\n'
         % (MP, PY, cmd, cmd))
    u = ('#!/bin/sh\ncase "$1" in *KSDISK*|*sda1*) ;; *) exit 0;; esac\ncru d freenodes 2>/dev/null\n%s --stop\nexit 0\n' % cmd)
    open(H + "/M91freenodes.sh", "w").write(m)
    open(H + "/U76freenodes.sh", "w").write(u)
    os.chmod(H + "/M91freenodes.sh", 0o755)
    os.chmod(H + "/U76freenodes.sh", 0o755)
    sh(["cru", "d", "freenodes"])
    sh(["cru", "a", "freenodes", "50 * * * * %s --scheduled" % cmd])
    serve()
    print("已安装。订阅地址（在 Merlin Clash 里添加）：")
    print("  配置完整版： http://%s:%d/full.yaml" % (BIND, PORT))
    print("  仅节点版：   http://%s:%d/free.yaml" % (BIND, PORT))
    print("现在执行  %s --now  先跑第一轮。" % cmd)


def uninstall():
    stop()
    sh(["cru", "d", "freenodes"])
    for f in ("M91freenodes.sh", "U76freenodes.sh"):
        try:
            os.remove("/koolshare/init.d/" + f)
        except OSError:
            pass
    print("已卸载（U 盘上的文件没有删）")


def main():
    a = sys.argv[1:]
    if "--install" in a:
        install()
    elif "--uninstall" in a:
        uninstall()
    elif "--diag" in a:
        diag()
    elif "--serve" in a:
        serve()
    elif "--stop" in a:
        stop()
    elif "--report" in a:
        print(open(WWW + "/report.txt", encoding="utf-8").read())
    elif "--now" in a or "--scheduled" in a:
        if yaml is None:
            raise SystemExit("缺少 PyYAML：/opt/bin/opkg install python3-yaml")
        serve()
        if "--scheduled" in a:
            if time.gmtime(time.time() + 8 * 3600).tm_hour not in SCHED_HOURS or time.gmtime().tm_year < 2026:
                return
        run()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
