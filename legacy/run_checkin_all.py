# -*- coding: utf-8 -*-
"""复刻前端「一键执行」按钮：对每个有凭据的平台起异步 job，并行轮询聚合进度。"""
import json, sys, time, urllib.request

BASE = "http://127.0.0.1:8799"
# 用法: python run_checkin_all.py [task ...]   默认仅 checkin
TASKS = sys.argv[1:] or ["checkin"]


def post(path, payload):
    req = urllib.request.Request(BASE + path,
                                 data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=120))


def get(path):
    return json.load(urllib.request.urlopen(BASE + path, timeout=120))


def main():
    st = get("/api/state")
    # 只对「声明支持该任务」的平台发起，避免刷出一片「未知任务」失败
    plats = [pid for pid, p in st["platforms"].items()
             if p.get("has_credentials")
             and any(t["key"] in TASKS for t in (p.get("tasks") or []))]
    print("任务:", TASKS)
    print("平台:", ", ".join(plats))

    jobs = []
    for pid in plats:
        try:
            res = post("/api/run", {"platform": pid, "tasks": TASKS, "async": True})
            if res.get("ok") and res.get("job"):
                jobs.append({"pid": pid, "jid": res["job"]})
                print("  启动 %-12s job=%s accounts=%s total=%s" % (pid, res["job"], res.get("accounts"), res.get("total")))
            else:
                print("  启动失败 %-12s %s" % (pid, res.get("error")))
        except Exception as e:
            print("  启动异常 %-12s %s" % (pid, e))
    if not jobs:
        print("未启动任何任务")
        return

    t0 = time.time()
    finished = set()
    while time.time() - t0 < 360:
        time.sleep(0.6)
        for j in jobs:
            if j["jid"] in finished:
                continue
            p = get("/api/progress?job=" + j["jid"])
            if p.get("finished"):
                finished.add(j["jid"])
                j["results"] = p.get("results") or []
                j["error"] = p.get("error")
        if len(finished) == len(jobs):
            break

    print("\n" + "=" * 72)
    ok_n = fail_n = 0
    for j in jobs:
        print("\n[%s]" % j["pid"])
        if j.get("error"):
            print("  ERROR:", j["error"])
        for r in j.get("results", []):
            for s in r.get("steps", []):
                flag = "OK " if s.get("ok") else "FAIL"
                if s.get("ok"):
                    ok_n += 1
                else:
                    fail_n += 1
                print("  %s %-16s %s" % (flag, r.get("name"), s.get("msg")))
    print("\n" + "=" * 72)
    print("成功 %d 项 / 失败 %d 项" % (ok_n, fail_n))

    out = {"ok": ok_n, "fail": fail_n,
           "detail": [{"platform": j["pid"], "results": j.get("results", []), "error": j.get("error")} for j in jobs]}
    with open("last_checkin_%s.json" % "_".join(TASKS), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
