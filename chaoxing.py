#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chaoxing (超星学习通) CLI - 登录部分
- 账号密码登录  /fanyalogin        (AES-CBC u2oh6Vu^HWe4_AES)
- 短信验证码登录 /fanyaloginbycode
- 学习通APP扫码登录 (createqr + getauthstatus 轮询)
- cookie 持久化 ~/.chaoxing/cookies.txt
"""
import os
import sys
import time
import json
import random
import base64
import argparse
import tempfile

import requests
import pyaes

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
AES_KEY = "u2oh6Vu^HWe4_AES"
PASSPORT = "https://passport2.chaoxing.com"
DEFAULT_REFER = "https://i.chaoxing.com"
PC_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
         "(KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36")
HEADERS = {
    "User-Agent": PC_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Connection": "keep-alive",
    "sec-ch-ua": '"Chromium";v="118", "Google Chrome";v="118", "Not=A?Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
}
QR_POLL_INTERVAL = 3          # 轮询间隔(秒)
QR_POLL_LIMIT = 55            # 最大轮询次数(前端 code>=50 视为失效)


def config_dir() -> str:
    d = os.path.join(os.path.expanduser("~"), ".chaoxing")
    os.makedirs(d, exist_ok=True)
    return d


def cookies_path() -> str:
    return os.path.join(config_dir(), "cookies.txt")


def qrcode_image_path() -> str:
    return os.path.join(config_dir(), "qrcode.png")


# ---------------------------------------------------------------------------
# AES 加密 (对齐 passport 前端 CryptoJS.AES.encrypt)
#   mode CBC, key=iv=u2oh6Vu^HWe4_AES, PKCS7 padding, 输出 base64
# ---------------------------------------------------------------------------
class AESCipher:
    def __init__(self, key=AES_KEY):
        self.key = key.encode("utf-8")
        self.iv = key.encode("utf-8")

    @staticmethod
    def _pkcs7_pad(b: bytes, block_size=16) -> bytes:
        pad = block_size - (len(b) % block_size)
        return b + bytes([pad]) * pad

    def encrypt(self, plaintext: str) -> str:
        """CBC 链式加密, 支持任意长度 (pyaes 需按 16 字节整块喂入)"""
        cbc = pyaes.AESModeOfOperationCBC(self.key, self.iv)
        data = self._pkcs7_pad(plaintext.encode("utf-8"))
        out = b""
        block_size = 16
        for i in range(0, len(data), block_size):
            out += cbc.encrypt(data[i:i + block_size])
        return base64.b64encode(out).decode("utf-8")


cipher = AESCipher()


# ---------------------------------------------------------------------------
# Cookie 读写
# ---------------------------------------------------------------------------
def save_cookies(session: requests.Session) -> None:
    pairs = [f"{k}={session.cookies.get(k)}" for k in session.cookies.keys()]
    with open(cookies_path(), "w", encoding="utf-8") as f:
        f.write(";".join(pairs))
    print(f"[chaoxing] cookie 已保存 -> {cookies_path()}")


def load_cookies_dict() -> dict:
    path = cookies_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read().strip()
        return dict(it.split("=", 1) for it in raw.split(";") if "=" in it)
    except Exception:
        return {}


def new_session(with_cookies=True) -> requests.Session:
    s = requests.Session()
    s.headers.update(HEADERS)
    if with_cookies:
        s.cookies.update(load_cookies_dict())
    return s


# ---------------------------------------------------------------------------
# 登录校验
# ---------------------------------------------------------------------------
def validate_session(session: requests.Session) -> bool:
    """通过获取用户信息接口判断登录态是否有效。"""
    if not (session.cookies.get("_uid") or session.cookies.get("UID")):
        return False
    try:
        # 获取用户空间信息
        r = session.get("https://i.chaoxing.com/space/index?t=" + str(int(time.time())),
                        timeout=10, allow_redirects=False)
        if r.status_code == 302 and "login" in r.headers.get("Location", "").lower():
            return False
        return True
    except requests.RequestException:
        return False


# ---------------------------------------------------------------------------
# ① 账号密码登录 /fanyalogin
# ---------------------------------------------------------------------------
def login_password(phone: str, password: str, fid: str = "-1") -> dict:
    session = new_session(with_cookies=False)
    url = f"{PASSPORT}/fanyalogin"
    data = {
        "fid": fid,
        "uname": cipher.encrypt(phone),
        "password": cipher.encrypt(password),
        "refer": requests.utils.quote(DEFAULT_REFER, safe=""),
        "t": "true",
        "forbidotherlogin": "0",
        "validate": "",
        "doubleFactorLogin": "0",
        "independentId": "0",
        "independentNameId": "0",
    }
    r = session.post(url, headers=HEADERS, data=data, timeout=15)
    try:
        j = r.json()
    except ValueError:
        return {"status": False, "msg": f"非预期响应: {r.text[:200]}"}
    if j.get("status"):
        # 跟随服务端下发的 url 跳转, 补全登录态 cookie (同前端 window.location)
        jump = j.get("url") or ""
        if jump:
            try:
                session.get(requests.utils.unquote(jump), headers=HEADERS,
                            timeout=15, allow_redirects=True)
            except requests.RequestException:
                pass
        save_cookies(session)
        return {"status": True, "msg": "登录成功",
                "uid": session.cookies.get("_uid") or session.cookies.get("UID")}
    if j.get("weakpwd"):
        return {"status": False, "msg": "密码为弱密码, 需前往"
                                       f"{PASSPORT}/v11/updateweakpwd 修改后再登录"}
    if j.get("containTwoFactorLogin"):
        return {"status": False, "msg": "需二次验证, 请改用扫码或验证码登录"}
    return {"status": False, "msg": j.get("msg2") or j.get("msg") or "登录失败"}


# ---------------------------------------------------------------------------
# ② 短信验证码登录 /fanyaloginbycode
#   verCode = AES(验证码) 后 URL-encode
# ---------------------------------------------------------------------------
def login_smscode(phone: str, code: str, fid: str = "-1",
                  double_factor: str = "0", indep_name_id: str = "0") -> dict:
    session = new_session(with_cookies=False)
    url = f"{PASSPORT}/fanyaloginbycode"
    ver = requests.utils.quote(cipher.encrypt(code), safe="")
    data = {
        "fid": fid,
        "uname": phone,
        "verCode": ver,
        "refer": requests.utils.quote(DEFAULT_REFER, safe=""),
        "doubleFactorLogin": double_factor,
        "independentNameId": indep_name_id,
    }
    r = session.post(url, headers=HEADERS, data=data, timeout=15)
    try:
        j = r.json()
    except ValueError:
        return {"status": False, "msg": f"非预期响应: {r.text[:200]}"}
    if j.get("status"):
        save_cookies(session)
        return {"status": True, "msg": "登录成功",
                "uid": session.cookies.get("_uid") or session.cookies.get("UID")}
    return {"status": False, "msg": j.get("msg2") or j.get("msg") or "登录失败"}


# ---------------------------------------------------------------------------
# ③ 学习通APP扫码登录
#   GET  /mlogin             -> 解析 uuid / enc (服务端生成)
#   GET  /createqr?uuid=..   -> 二维码图片(让手机扫)
#   POST /getauthstatus      -> 轮询扫码结果
# ---------------------------------------------------------------------------
def load_text_field(html: str, field_id: str) -> str:
    """从服务端渲染的 html 中提取 <input id=... value=...>。"""
    import re
    m = re.search(r'id="%s"[^>]*value="([^"]*)"' % re.escape(field_id), html)
    if not m:
        m = re.search(r'value="([^"]*)"[^>]*id="%s"' % re.escape(field_id), html)
    return m.group(1) if m else ""


def login_qrcode(fid: str = "-1", save_image: bool = True,
                 save_ascii: bool = True, timeout: int = None) -> dict:
    session = new_session(with_cookies=False)
    refer = requests.utils.quote(DEFAULT_REFER, safe="")
    page_url = f"{PASSPORT}/mlogin?fid={fid}&newversion=true&refer={refer}"

    # 1) 拉取登录页, 拿到 uuid / enc
    r = session.get(page_url, headers=HEADERS, timeout=15)
    html = r.text
    uuid = load_text_field(html, "uuid")
    enc = load_text_field(html, "enc")
    if not uuid or not enc:
        return {"status": False, "msg": "未能从登录页解析二维码参数(uuid/enc)"}

    # 2) 获取二维码图片
    qr_url = f"{PASSPORT}/createqr?uuid={uuid}&fid={fid}"
    img = session.get(qr_url, headers=HEADERS, timeout=15).content
    if save_image:
        img_path = qrcode_image_path()
        with open(img_path, "wb") as f:
            f.write(img)
        print(f"[chaoxing] 二维码图片已保存 -> {img_path}")
    if save_ascii:
        ascii_qr = render_ascii_qr(img)
        if ascii_qr:
            print("[chaoxing] ── 请用「学习通APP」扫描下方二维码登录 ──")
            print(ascii_qr)
            print("[chaoxing] ─────────────────────────────────────")
        else:
            # 解码失败时退化为仅提示图片
            print(f"[chaoxing] 请打开 {qrcode_image_path()} 并用「学习通APP」扫码登录")

    # 3) 轮询 getauthstatus
    poll_url = f"{PASSPORT}/getauthstatus"
    t0 = time.time()
    polls = 0
    wait_msg = False
    while polls < QR_POLL_LIMIT:
        if timeout and (time.time() - t0) > timeout:
            return {"status": False, "msg": "扫码登录超时"}
        try:
            rr = session.post(poll_url, headers=HEADERS, data={"enc": enc, "uuid": uuid},
                              timeout=12)
            j = rr.json()
        except Exception as e:
            return {"status": False, "msg": f"轮询异常: {e}"}
        polls += 1
        if j.get("status"):
            # 登录成功: 服务端已通过 Set-Cookie 写入登录态; 再跟随下发 url 兜底
            jump = j.get("url") or DEFAULT_REFER
            try:
                session.get(jump, headers=HEADERS, timeout=15, allow_redirects=True)
            except requests.RequestException:
                pass
            save_cookies(session)
            return {"status": True, "msg": "登录成功",
                    "uid": session.cookies.get("_uid") or session.cookies.get("UID")}
        jtype = j.get("type")
        if jtype == 4:          # 已扫, 等确认
            if not wait_msg:
                print("[chaoxing] 已扫码, 请在手机APP上点击「确认登录」...")
                wait_msg = True
        elif jtype == 6:        # 用户取消, 需刷新二维码
            return {"status": False, "msg": "已取消扫码, 请重新运行"}
        else:
            if not wait_msg:
                print(f"[chaoxing] 等待扫码... ({j.get('mes', '')})")
        time.sleep(QR_POLL_INTERVAL)
    return {"status": False, "msg": "二维码已失效, 请重试"}


def decode_qr_content(png_bytes: bytes) -> str:
    """解析 createqr 图片包含的真实授权 URL(用于终端 ASCII 二维码)。
    依赖 pyzbar；若不可用则返回空串。"""
    try:
        import io
        from pyzbar.pyzbar import decode as _d
        from PIL import Image
        img = Image.open(io.BytesIO(png_bytes))
        hits = _d(img)
        if hits:
            return hits[0].data.decode("utf-8", "ignore")
    except Exception:
        pass
    return ""


def render_ascii_qr(png_bytes: bytes) -> str:
    """用解码出的内容, 重新生成适合终端显示的 ASCII 二维码。"""
    try:
        import qrcode
        from qrcode.constants import ERROR_CORRECT_M, ERROR_CORRECT_L
    except Exception:
        return ""
    content = decode_qr_content(png_bytes)
    if not content:
        return ""
    try:
        qr = qrcode.QRCode(
            version=1, error_correction=ERROR_CORRECT_L, box_size=1, border=1)
        qr.add_data(content)
        qr.make(fit=True)
        img = qr.get_matrix()
    except Exception:
        return ""
    lines = []
    for row in img:
        lines.append("".join("██" if c else "  " for c in row))
    return "\n".join(lines)


def cmd_login(args) -> int:
    # 已有 cookie 且有效
    if not args.force and not args.phone and not args.qrcode and not args.code:
        s = new_session()
        if validate_session(s):
            print(f"[chaoxing] 已登录 (uid={s.cookies.get('_uid') or s.cookies.get('UID')})")
            return 0
        print("[chaoxing] cookie 不存在或已失效")

    if args.phone:
        if not args.password:
            import getpass
            args.password = getpass.getpass("密码: ")
        res = login_password(args.phone, args.password, args.fid)
    elif args.qrcode:
        res = login_qrcode(args.fid)
    elif args.code:
        if not args.phone:
            print("[chaoxing] 验证码登录需提供 --phone")
            return 1
        res = login_smscode(args.phone, args.code, args.fid)
    else:
        print("[chaoxing] 请提供登录方式: --phone 或 --qrcode 或 --code")
        return 1

    if res.get("status"):
        print(f"[chaoxing] ✅ {res['msg']}")
        return 0
    print(f"[chaoxing] ❌ {res.get('msg')}")
    return 1


def cmd_status(args) -> int:
    s = new_session()
    if validate_session(s):
        print("[chaoxing] ✅ 已登录")
        print(f"  uid      : {s.cookies.get('_uid') or s.cookies.get('UID')}")
        print(f"  fid      : {s.cookies.get('fid')}")
        print(f"  cookies  : {cookies_path()}")
        return 0
    print("[chaoxing] ❌ 未登录或 cookie 已失效 (运行 `chaoxing login`)")
    return 1


def cmd_logout(args) -> int:
    path = cookies_path()
    if os.path.exists(path):
        os.remove(path)
        print("[chaoxing] 已清除本地 cookie")
    return 0


# ---------------------------------------------------------------------------
# 课程列表
# ---------------------------------------------------------------------------
def _decode_course_list(html_text: str) -> list:
    """解析 courselistdata 返回的课程列表 HTML。
    返回字段含 status: 进行中 / 课程已结束 / 未开放。"""
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html_text, "lxml")
    out = []
    for div in soup.select("div.course"):
        try:
            tip = div.select_one("a.not-open-tip, div.not-open-tip")
            status = tip.get_text(strip=True) if tip else "进行中"
            # cpi 优先取 input.cpi / curPersonId, 否则从 stucoursemiddle href 兜底
            cpi = ""
            for sel in ("input.cpi", "input.curPersonId"):
                e = div.select_one(sel)
                if e and e.get("value"):
                    cpi = e["value"]
                    break
            a = div.select_one("a")
            href = a.get("href") if a else ""
            import re as _re
            if not cpi and href:
                m = _re.search(r"cpi=(\d+)", href)
                if m:
                    cpi = m.group(1)
            if not cpi:
                continue  # 连链接都没有则视为占位/无用节点
            cd = {
                "id": div.get("id"),
                "status": status,  # 课程已结束 / 进行中 / 未开放
                "clazzId": div.select_one("input.clazzId")["value"]
                           if div.select_one("input.clazzId") else "",
                "courseId": div.select_one("input.courseId")["value"]
                            if div.select_one("input.courseId") else "",
                "cpi": cpi,
                "url": href or "",
                "title": (div.select_one("span.course-name") or {}).get("title", "")
                         if div.select_one("span.course-name") else "",
                "teacher": (div.select_one("p.color3") or {}).get("title", "")
                           if div.select_one("p.color3") else "",
                "desc": (div.select_one("p.margint10") or {}).get("title", "")
                        if div.select_one("p.margint10") else "",
            }
            out.append(cd)
        except Exception:
            continue
    return out


def _decode_course_folder(html_text: str) -> list:
    """解析 interaction 页面的二级课程文件夹。"""
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html_text, "lxml")
    folders = []
    for li in soup.select("ul.file-list>li"):
        fileid = li.get("fileid")
        if not fileid:
            continue
        inp = li.select_one("input.rename-input")
        folders.append({"id": fileid,
                        "name": inp["value"] if inp else ""})
    return folders


def get_course_list(session: requests.Session) -> list:
    """拉取(含二级文件夹的)全部课程列表。"""
    base = "https://mooc2-ans.chaoxing.com/mooc2-ans"
    referer = (base + "/visit/interaction?moocDomain="
               "https://mooc1-1.chaoxing.com/mooc-ans")
    h = {"Referer": referer}
    data = {"courseType": 1, "courseFolderId": 0, "query": "",
            "superstarClass": 0}

    r = session.post(f"{base}/visit/courselistdata", headers=h, data=data,
                     timeout=15)
    courses = _decode_course_list(r.text)

    # 二级文件夹
    try:
        ir = session.get(base + "/visit/interaction", headers=h, timeout=15)
        for folder in _decode_course_folder(ir.text):
            d = dict(data, courseFolderId=folder["id"])
            rr = session.post(f"{base}/visit/courselistdata", headers=h,
                              data=d, timeout=15)
            fold_courses = _decode_course_list(rr.text)
            for c in fold_courses:
                c["folder"] = folder["name"]
            courses += fold_courses
    except requests.RequestException:
        pass

    return courses


def cmd_courses(args) -> int:
    s = new_session(with_cookies=True)
    if not validate_session(s):
        print("[chaoxing] ❌ 未登录或 cookie 已失效 (运行 `chaoxing login`)")
        return 1
    courses = get_course_list(s)
    if not courses:
        print("[chaoxing] 暂无课程(或需要先加入课堂)")
        return 0
    # 过滤
    if args.ended or args.status:
        kw = args.status or "已结束"
        courses = [c for c in courses if kw in c.get("status", "")]
        if not courses:
            print(f"[chaoxing] 没有状态匹配「{kw}」的课程")
            return 0
    if args.json:
        import json
        print(json.dumps(courses, ensure_ascii=False, indent=2))
        return 0
    # 状态统计
    from collections import Counter
    cnt = Counter(c.get("status", "?") for c in courses)
    print(f"[chaoxing] 共 {len(courses)} 门课程 "
          f"(进行中{cnt.get('进行中', 0)} / 已结束{cnt.get('课程已结束', 0)} / "
          f"其他{cnt.get('未开放', 0)}):\n")
    for i, c in enumerate(courses, 1):
        folder = f" [{c.get('folder', '')}]" if c.get("folder") else ""
        status = c.get("status", "")
        tag = " [已结课]" if status in ("课程已结束", "已结束") else ""
        print(f"  {i:>2}. [{status}]{tag} {c['title']}{folder}")
        print(f"      id={c['id']}  courseId={c['courseId']}  "
              f"clazzId={c['clazzId']}  cpi={c['cpi']}  教师={c['teacher']}")
    return 0


# ---------------------------------------------------------------------------
# 章节 & 刷课进度
# ---------------------------------------------------------------------------
def _resolve_course(session, selector: str) -> dict:
    """按序号或 courseId 从课程列表里选一门课。"""
    courses = get_course_list(session)
    if not selector:
        print("[chaoxing] 选择课程:")
        for i, c in enumerate(courses, 1):
            print(f"  {i:>2}. {c['title']}  (courseId={c['courseId']})")
        try:
            sel = input("[chaoxing] 请输入课程序号: ").strip()
        except EOFError:
            sel = ""
        if not sel.isdigit():
            raise SystemExit("[chaoxing] 未选择课程")
        return courses[int(sel) - 1]
    if selector.isdigit():
        cid = selector
        for i, c in enumerate(courses, 1):
            if str(i) == str(int(selector)) and int(selector) <= len(courses):
                return courses[int(selector) - 1]
        for i, c in enumerate(courses, 1):
            if c["courseId"] == cid or c["clazzId"] == cid:
                return c
    # 按名称模糊
    matches = [c for c in courses if selector in c["title"]]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print(f"[chaoxing] 找到 {len(matches)} 门同名课程, 请选择:")
        for i, c in enumerate(matches, 1):
            print(f"  {i}. {c['title']}  (courseId={c['courseId']} clazzId={c['clazzId']} "
                  f"状态={c.get('status', '?')})")
        try:
            sel = input("[chaoxing] 请输入序号: ").strip()
        except EOFError:
            raise SystemExit("[chaoxing] 未选择课程")
        if sel.isdigit() and 1 <= int(sel) <= len(matches):
            return matches[int(sel) - 1]
        raise SystemExit("[chaoxing] 无效选择")
    raise SystemExit(f"[chaoxing] 未找到课程匹配: {selector}")


def get_chapter_points(session: requests.Session, course: dict) -> list:
    """拉取一门课的所有章节(章)与其下任务点统计。"""
    from bs4 import BeautifulSoup
    url = ("https://mooc2-ans.chaoxing.com/mooc2-ans/mycourse/studentcourse"
           f"?courseid={course['courseId']}&clazzid={course['clazzId']}"
           f"&cpi={course['cpi']}&ut=s")
    h = {"Referer": "https://mooc2-ans.chaoxing.com/"}
    r = session.get(url, headers=h, timeout=20)
    soup = BeautifulSoup(r.text, "lxml")

    # 顶层章容器: chapter_td 下的第一级 chapter_unit
    chapters = soup.select(".chapter_td > .chapter_unit")
    out = []
    for ch in chapters:
        name_el = ch.select_one(".catalog_name span[title]") or \
                  ch.select_one(".catalog_name")
        name = (name_el.get("title") or name_el.get_text(strip=True)
                if name_el else "未命名章")
        pts = []
        for item in ch.select("div.chapter_item[id^=cur]"):
            title = item.select_one("a.clicktitle") or \
                    item.select_one(".catalog_name")
            t = title.get_text(strip=True) if title else ""
            tip = item.select_one("span.bntHoverTips")
            done = bool(tip and "已完成" in tip.get_text())
            jb = item.select_one("input.knowledgeJobCount")
            job = int(jb["value"]) if jb and jb.get("value", "").isdigit() else 0
            pts.append({"id": item.get("id"), "title": t,
                        "done": done, "job": job})
        done = sum(1 for p in pts if p["done"])
        out.append({"name": name, "points": pts,
                    "done": done, "total": len(pts)})
    return out


def cmd_chapters(args) -> int:
    s = new_session(with_cookies=True)
    if not validate_session(s):
        print("[chaoxing] ❌ 未登录或 cookie 已失效 (运行 `chaoxing login`)")
        return 1
    course = _resolve_course(s, args.course)
    chapters = get_chapter_points(s, course)
    print(f"[chaoxing] 《{course['title']}》 章节列表 ({len(chapters)} 章):\n")
    for i, ch in enumerate(chapters, 1):
        print(f"  {i:>2}. {ch['name'].strip()}  —— 任务点 {ch['total']} 个")
    return 0


def cmd_progress(args) -> int:
    s = new_session(with_cookies=True)
    if not validate_session(s):
        print("[chaoxing] ❌ 未登录或 cookie 已失效 (运行 `chaoxing login`)")
        return 1
    if args.all:
        courses = get_course_list(s)
    else:
        courses = [_resolve_course(s, args.course)]

    print("[chaoxing] 刷课进度:\n")
    for ci, course in enumerate(courses, 1):
        try:
            chapters = get_chapter_points(s, course)
        except Exception as e:
            print(f"  {ci:>2}. {course['title']}  —— 获取失败: {e}")
            continue
        total = sum(c["total"] for c in chapters)
        done = sum(c["done"] for c in chapters)
        pct = (done / total * 100) if total else 0
        bar = _bar(pct)
        print(f"  {ci:>2}. {course['title']}   [{bar}] {done}/{total}  ({pct:.1f}%)")
    return 0


def _bar(pct: float, width: int = 18) -> str:
    n = int(round(pct / 100 * width))
    return "█" * n + "░" * (width - n)


# ---------------------------------------------------------------------------
# 任务点目录 (knowledge/cards) 与用户信息
# ---------------------------------------------------------------------------
JOB_TYPE_LABEL = {
    "video": "视频", "audio": "音频", "document": "文档",
    "workid": "答题", "read": "阅读", "live": "直播",
}

def get_knowledge_jobs(session: requests.Session, course: dict,
                       knowledgeid: str) -> dict:
    """获取指定知识点下的任务目录。返回 {status, cards, defaults, name}"""
    import re, json as _json
    params = {
        "clazzid": course["clazzId"], "courseid": course["courseId"],
        "knowledgeid": knowledgeid, "ut": "s", "cpi": course["cpi"],
        "v": "2025-0424-1038-3", "mooc2": "1", "num": "0",
    }
    try:
        r = session.get("https://mooc1.chaoxing.com/mooc-ans/knowledge/cards",
                        params=params, headers=HEADERS, timeout=20)
    except requests.RequestException as e:
        return {"status": False, "msg": str(e)}
    html = r.text
    if "章节未开放" in html:
        return {"status": True, "notOpen": True, "cards": [], "defaults": {},
                "name": ""}
    m = re.search(r"mArg=\{(.*?)\};", html.replace(" ", ""), re.S)
    if not m:
        return {"status": False, "msg": "未找到任务数据(mArg)"}
    try:
        d = _json.loads("{" + m.group(1) + "}")
    except Exception as e:
        return {"status": False, "msg": f"解析失败: {e}"}
    cards = d.get("attachments", [])
    out = []
    for c in cards:
        if "otherinfo" not in c and "otherInfo" in c:
            c["otherinfo"] = c["otherInfo"].split("&")[0]
        prop = c.get("property", {}) or {}
        ctype = (c.get("type") or prop.get("type") or "").lower()
        jobid = c.get("jobid") or c.get("id") or ""
        out.append({
            "type": ctype,
            "jobid": str(jobid),
            "name": prop.get("name") or prop.get("title") or c.get("name") or "",
            "isPassed": bool(c.get("isPassed", False)),
            "mid": c.get("mid", ""),
            "objectId": c.get("objectId", "") or prop.get("objectid", ""),
            "aid": c.get("aid", ""),
            "enc": c.get("enc", ""),
            "jtoken": c.get("jtoken", ""),
            "otherinfo": c.get("otherinfo", ""),
            "playTime": c.get("playTime", 0),
            "rt": prop.get("rt", "") or c.get("rt", ""),
            "attDuration": c.get("attDuration", ""),
            "attDurationEnc": c.get("attDurationEnc", ""),
            "videoFaceCaptureEnc": c.get("videoFaceCaptureEnc", ""),
        })
    return {"status": True, "notOpen": False, "cards": out,
            "defaults": d.get("defaults", {}),
            "name": d.get("knowledgename", "")}


def _strip_kid(kid: str) -> str:
    """去掉知识点ID的 cur 前缀, 用于 knowledge/cards 接口。"""
    k = kid if not str(kid).startswith("cur") else str(kid)[3:]
    return k


def cmd_jobs(args) -> int:
    s = new_session(with_cookies=True)
    if not validate_session(s):
        print("[chaoxing] ❌ 未登录或 cookie 已失效 (运行 `chaoxing login`)")
        return 1
    course = _resolve_course(s, args.course)
    chapters = get_chapter_points(s, course)
    # 选章节
    ch_index = args.point
    if ch_index is not None:
        if 1 <= ch_index <= len(chapters):
            chapters = [chapters[ch_index - 1]]
        else:
            print(f"[chaoxing] 章节序号越界(共{len(chapters)}章)")
            return 1
    if args.json:
        import json as _json
        out = []
        for ch in chapters:
            for p in ch["points"]:
                kj = get_knowledge_jobs(s, course, _strip_kid(p["id"]))
                out.append({"chapter": ch["name"], "knowledge": p["title"],
                            "knowledgeId": p["id"],
                            "jobs": kj.get("cards", [])})
        print(_json.dumps(out, ensure_ascii=False, indent=2))
        return 0
    for ch in chapters:
        print(f"[章节] {ch['name'].strip()}  (任务点 {ch['total']} 个)\n")
        for p in ch["points"]:
            kd = "✔已完成" if p["done"] else "○待学"
            print(f"  ├ {kd} {p['title']}  (id={p['id']})")
            kj = get_knowledge_jobs(s, course, _strip_kid(p["id"]))
            for j in kj.get("cards", []):
                kind = JOB_TYPE_LABEL.get(j["type"], j["type"] or "?")
                js = "✔" if j["isPassed"] else "·"
                print(f"  │   {js} [{kind}] {j['name']}  (jobid={j['jobid']})")
            if not kj.get("cards"):
                print(f"  │   (无任务或未开放)")
        print()
    return 0


def cmd_whoami(args) -> int:
    s = new_session(with_cookies=True)
    if not validate_session(s):
        print("[chaoxing] ❌ 未登录或 cookie 已失效 (运行 `chaoxing login`)")
        return 1
    uid = s.cookies.get("_uid") or s.cookies.get("UID")
    print(f"[chaoxing] 用户ID      : {uid}")
    print(f"[chaoxing] 学习空间fid : {s.cookies.get('fid')}")
    try:
        r = s.get("https://i.chaoxing.com/base", headers=HEADERS, timeout=12)
        import re as _re
        m = _re.search(r'"nickname"\s*:\s*"([^"]+)"', r.text)
        if m:
            print(f"[chaoxing] 昵称        : {m.group(1)}")
    except requests.RequestException:
        pass
    return 0


# ---------------------------------------------------------------------------
# 思考讨论 (insertbbs / groupweb topic v3)
# ---------------------------------------------------------------------------
def get_discuss_topics(session: requests.Session, course: dict,
                       knowledgeid: str) -> list:
    """获取知识点下的思考讨论话题 (knowledge/cards num=2, module=insertbbs)。
    返回 [{mid, jobid, title, aid}]"""
    import re, json as _json
    params = {
        "clazzid": course["clazzId"], "courseid": course["courseId"],
        "knowledgeid": knowledgeid, "ut": "s", "cpi": course["cpi"],
        "v": "2025-0424-1038-3", "mooc2": "1", "num": "2",
    }
    try:
        r = session.get("https://mooc1.chaoxing.com/mooc-ans/knowledge/cards",
                        params=params, headers=HEADERS, timeout=20)
    except requests.RequestException:
        return []
    m = re.search(r"mArg=\{(.*?)\};", r.text.replace(" ", ""), re.S)
    if not m:
        return []
    try:
        d = _json.loads("{" + m.group(1) + "}")
    except Exception:
        return []
    out = []
    for a in d.get("attachments", []):
        prop = a.get("property", {}) or {}
        if prop.get("module") != "insertbbs":
            continue
        out.append({
            "mid": str(a.get("mid", "")),          # mtopicid
            "jobid": str(a.get("jobid", "")),
            "title": prop.get("title", ""),
            "aid": a.get("aid", ""),
        })
    return out


def get_topic_status(session: requests.Session, course: dict,
                     knowledgeid: str, mtopicid: str, jobid: str) -> dict:
    """查询讨论话题完成状态 + 解析 groupweb 链接(bbsid/topic_uuid)。
    返回 {isFinished(bool), bbsid, topic_uuid, group_url}"""
    import re
    params = {
        "mtopicid": mtopicid, "jobid": jobid, "isPortal": "false",
        "knowledgeid": knowledgeid, "ut": "s", "clazzId": course["clazzId"],
        "enc": "", "utenc": "undefined", "courseid": course["courseId"],
        "isJob": "false",
    }
    res = {"isFinished": False, "bbsid": "", "topic_uuid": "", "group_url": ""}
    try:
        r = session.get("https://mooc1.chaoxing.com/mooc-ans/bbscircle/chapter",
                        params=params, headers=HEADERS, timeout=20)
    except requests.RequestException:
        return res
    m = re.search(r'id="isFinished" value="([^"]*)"', r.text)
    res["isFinished"] = bool(m and m.group(1) == "true")
    m2 = re.search(r'data="(https://groupweb[^"]*replysList[^"]*)"', r.text)
    if m2:
        url = m2.group(1)
        res["group_url"] = url
        mm = re.search(r"/bbs/([0-9a-f]+)/([0-9a-f]+)/replysList", url)
        if mm:
            res["bbsid"] = mm.group(1)
            res["topic_uuid"] = mm.group(2)
    return res


def fetch_url_token(session: requests.Session, group_url: str) -> str:
    """从 replysList 页面解析 urlToken (提交回复必需)。"""
    import re
    try:
        r = session.get(group_url, headers=HEADERS, timeout=20)
        m = re.search(r"urlToken:\s*'([0-9a-f]{32})'", r.text)
        return m.group(1) if m else ""
    except requests.RequestException:
        return ""


def add_discuss_reply(session: requests.Session, course: dict,
                      bbsid: str, topic_uuid: str, content: str,
                      url_token: str, anonymous: bool = False) -> dict:
    """提交讨论回复。返回 {status, msg, replyId}"""
    import uuid as _uuid
    url = f"https://groupweb.chaoxing.com/pc/invitation/{topic_uuid}/addReplys"
    data = {
        "courseId": course["courseId"], "classId": course["clazzId"],
        "replyId": "-1", "uuid": str(_uuid.uuid4()),
        "topic_content": content, "anonymous": "1" if anonymous else "",
        "urlToken": url_token, "bbsid": bbsid,
    }
    try:
        r = session.post(url, headers=HEADERS, data=data, timeout=20)
        j = r.json()
    except Exception as e:
        return {"status": False, "msg": f"请求异常: {e}"}
    if j.get("status"):
        return {"status": True, "msg": j.get("msg", ""),
                "replyId": j.get("datas", {}).get("replyId")}
    return {"status": False, "msg": j.get("msg") or str(j)[:120]}


def delete_discuss_reply(session: requests.Session, topic_uuid: str,
                         reply_uuid: str) -> dict:
    """删除讨论回复。reply_uuid 为回复的 uuid。"""
    url = (f"https://groupweb.chaoxing.com/pc/invitation/{topic_uuid}"
           f"/deleteReply?uuid={reply_uuid}")
    try:
        r = session.post(url, headers=HEADERS, timeout=20)
        j = r.json()
    except Exception as e:
        return {"status": False, "msg": f"请求异常: {e}"}
    return {"status": bool(j.get("status")), "msg": j.get("msg", "")}


def get_reply_list(session: requests.Session, bbsid: str, topic_uuid: str,
                   last_value: int = 0, order: int = 1, pages: int = 3) -> list:
    """分页拉取话题回复列表。返回 [{uuid, id, createrPuid, content, ...}]"""
    out = []
    for _ in range(pages):
        params = {"bbsid": bbsid, "uuid": topic_uuid,
                  "order": order, "lastValue": last_value}
        try:
            r = session.get("https://groupweb.chaoxing.com/pc/invitation/getReplyList",
                            params=params, headers=HEADERS, timeout=20)
            j = r.json()
        except Exception:
            break
        if not j.get("status"):
            break
        datas = j.get("datas") or []
        if not datas:
            break
        out.extend(datas)
        # 分页字段: 下一页用当前页最后一条回复的 id 作为 lastValue
        last_value = datas[-1].get("id", last_value)
    return out


def _collect_discuss(session, course, chapter_index: int = None) -> list:
    """收集课程所有讨论话题。返回 [{chapter, knowledge, knowledgeId, topic, status}]"""
    items = []
    chapters = get_chapter_points(session, course)
    if chapter_index is not None:
        if 1 <= chapter_index <= len(chapters):
            chapters = [chapters[chapter_index - 1]]
        else:
            raise SystemExit(f"[chaoxing] 章节序号越界(共{len(chapters)}章)")
    for ch in chapters:
        for p in ch["points"]:
            kid = _strip_kid(p["id"])
            for t in get_discuss_topics(session, course, kid):
                st = get_topic_status(session, course, kid, t["mid"], t["jobid"])
                items.append({"chapter": ch["name"], "knowledge": p["title"],
                              "knowledgeId": p["id"], "topic": t, "status": st})
    return items


def _find_discuss(session, course, selector) -> dict:
    """按 序号/topic_uuid/mid 定位讨论话题。"""
    items = _collect_discuss(session, course)
    if not items:
        raise SystemExit("[chaoxing] 该课程没有思考讨论话题")
    if selector is None:
        print("[chaoxing] 选择话题:")
        for i, it in enumerate(items, 1):
            mark = "✔已回复" if it["status"]["isFinished"] else "○未回复"
            print(f"  {i:>2}. {mark} {it['topic']['title'][:40]}")
        try:
            sel = input("[chaoxing] 请输入话题序号: ").strip()
        except EOFError:
            raise SystemExit("[chaoxing] 未选择话题")
        selector = sel
    if str(selector).isdigit() and 1 <= int(selector) <= len(items):
        return items[int(selector) - 1]
    for it in items:
        if it["topic"]["mid"] == str(selector) or \
           it["status"]["topic_uuid"] == str(selector):
            return it
    raise SystemExit(f"[chaoxing] 未找到话题: {selector}")


def cmd_discuss(args) -> int:
    s = new_session(with_cookies=True)
    if not validate_session(s):
        print("[chaoxing] ❌ 未登录或 cookie 已失效 (运行 `chaoxing login`)")
        return 1
    course = _resolve_course(s, args.course)
    items = _collect_discuss(s, course, args.point)
    if not items:
        print("[chaoxing] 该课程暂无思考讨论话题")
        return 0
    print(f"[chaoxing] 《{course['title']}》 思考讨论话题 ({len(items)} 个):\n")
    for i, it in enumerate(items, 1):
        st = it["status"]
        mark = "🟢" if st["isFinished"] else "🔴"
        state = "已回复(完成)" if st["isFinished"] else "未回复"
        print(f"  {i:>2}. {mark} {it['topic']['title']}")
        print(f"      [{state}] mid={it['topic']['mid']}  jobid={it['topic']['jobid']}")
        if it["status"]["topic_uuid"]:
            print(f"      uuid={it['status']['topic_uuid']}")
    return 0


def cmd_discuss_reply(args) -> int:
    s = new_session(with_cookies=True)
    if not validate_session(s):
        print("[chaoxing] ❌ 未登录或 cookie 已失效 (运行 `chaoxing login`)")
        return 1
    course = _resolve_course(s, args.course)
    it = _find_discuss(s, course, args.topic)
    st = it["status"]
    if not st["topic_uuid"] or not st["bbsid"]:
        print("[chaoxing] ❌ 无法解析话题的讨论链接")
        return 1
    token = fetch_url_token(s, st["group_url"])
    if not token:
        print("[chaoxing] ❌ 无法获取 urlToken")
        return 1
    res = add_discuss_reply(s, course, st["bbsid"], st["topic_uuid"],
                            args.content, token, args.anonymous)
    if res["status"]:
        print(f"[chaoxing] ✅ 回复发表成功 (replyId={res['replyId']})")
        st2 = get_topic_status(s, course, it["knowledgeId"],
                               it["topic"]["mid"], it["topic"]["jobid"])
        print(f"[chaoxing] 状态: {'🟢 已回复(完成)' if st2['isFinished'] else '🔴 未回复'}")
        return 0
    print(f"[chaoxing] ❌ {res['msg']}")
    return 1


def cmd_discuss_replies(args) -> int:
    s = new_session(with_cookies=True)
    if not validate_session(s):
        print("[chaoxing] ❌ 未登录或 cookie 已失效 (运行 `chaoxing login`)")
        return 1
    course = _resolve_course(s, args.course)
    it = _find_discuss(s, course, args.topic)
    st = it["status"]
    uid = s.cookies.get("_uid") or s.cookies.get("UID")
    replies = get_reply_list(s, st["bbsid"], st["topic_uuid"], pages=args.pages)
    print(f"[chaoxing] 《{it['topic']['title'][:30]}》 回复列表 ({len(replies)} 条):\n")
    for rp in replies:
        who = rp.get("createrPuid", "")
        me = " (我)" if str(who) == str(uid) else ""
        content = (rp.get("content") or "").replace("\n", " ")[:60]
        print(f"  - {rp.get('personName') or who}{me}: {content}")
        print(f"    uuid={rp.get('uuid')} id={rp.get('id')}")
    return 0


def cmd_discuss_delete(args) -> int:
    s = new_session(with_cookies=True)
    if not validate_session(s):
        print("[chaoxing] ❌ 未登录或 cookie 已失效 (运行 `chaoxing login`)")
        return 1
    course = _resolve_course(s, args.course)
    it = _find_discuss(s, course, args.topic)
    st = it["status"]
    if not args.reply:
        uid = s.cookies.get("_uid") or s.cookies.get("UID")
        replies = get_reply_list(s, st["bbsid"], st["topic_uuid"], pages=args.pages)
        mine = [r for r in replies if str(r.get("createrPuid", "")) == str(uid)]
        if not mine:
            print("[chaoxing] 该话题下没有找到我的回复")
            return 1
        if len(mine) == 1:
            args.reply = mine[0]["uuid"]
        else:
            print("[chaoxing] 我的回复:")
            for i, rp in enumerate(mine, 1):
                print(f"  {i}. {(rp.get('content') or '')[:50]}  uuid={rp.get('uuid')}")
            try:
                sel = input("选择要删除的回复序号: ").strip()
            except EOFError:
                raise SystemExit("[chaoxing] 未选择")
            args.reply = mine[int(sel) - 1]["uuid"]
    res = delete_discuss_reply(s, st["topic_uuid"], args.reply)
    if res["status"]:
        print(f"[chaoxing] ✅ {res['msg']}")
        return 0
    print(f"[chaoxing] ❌ {res['msg']}")
    return 1


# ---------------------------------------------------------------------------
# 刷课执行 (参考 SuperStar_R 逻辑: video/document/read/work/emptypage)
# ---------------------------------------------------------------------------
VIDEO_HEADERS = {**HEADERS, "Referer": "https://mooc1.chaoxing.com/ananas/modules/video/index.html?v=2025-0725-1842"}
AUDIO_HEADERS = {**HEADERS, "Referer": "https://mooc1.chaoxing.com/ananas/modules/audio/index_new.html?v=2025-0725-1842"}


def _ts() -> int:
    return int(time.time() * 1000)


def get_enc(clazzId, jobid, objectId, playingTime, duration, userid) -> str:
    import hashlib
    s = (f"[{clazzId}][{userid}][{jobid}][{objectId}]"
         f"[{playingTime * 1000}][d_yHJ!$pdA~5][{duration * 1000}][0_{duration}]")
    return hashlib.md5(s.encode()).hexdigest()


def get_video_info(session: requests.Session, course: dict, job: dict,
                   dtype: str = "Video") -> dict:
    """拉取视频资源信息 /ananas/status/<objectId>。返回 dict(含dtoken/duration)"""
    headers = VIDEO_HEADERS if dtype == "Video" else AUDIO_HEADERS
    fid = session.cookies.get("fid") or ""
    url = (f"https://mooc1.chaoxing.com/ananas/status/{job['objectId']}"
           f"?k={fid}&flag=normal")
    try:
        r = session.get(url, headers=headers, timeout=15)
        return r.json() if r.status_code == 200 else {}
    except Exception:
        return {}


def course_status(session: requests.Session, course: dict) -> str:
    """查询课程状态: 进行中 / 课程已结束 / 未知。"""
    try:
        for c in get_course_list(session):
            if str(c.get("courseId")) == str(course["courseId"]) and \
               str(c.get("clazzId")) == str(course["clazzId"]):
                return c.get("status", "进行中")
    except Exception:
        pass
    return "未知"


def video_progress_log(session: requests.Session, course: dict, job: dict,
                       dtoken: str, duration: int, playing_time: int,
                       dtype: str = "Video", _retried: bool = False) -> tuple:
    """视频进度上报。返回 (isPassed, status_code)。
    403 风控时自动刷新 dtoken 重试一次。"""
    headers = VIDEO_HEADERS if dtype == "Video" else AUDIO_HEADERS
    time.sleep(2)  # 防验证码限速 (参考项目 2s)
    userid = session.cookies.get("_uid") or session.cookies.get("UID") or ""
    enc = get_enc(course["clazzId"], job["jobid"], job["objectId"],
                  playing_time, duration, userid)
    params = {
        "clazzId": course["clazzId"], "playingTime": playing_time,
        "duration": duration, "clipTime": f"0_{duration}",
        "objectId": job["objectId"], "otherInfo": job["otherinfo"],
        "courseId": course["courseId"], "jobid": job["jobid"],
        "userid": userid, "isdrag": "3", "view": "pc", "enc": enc,
        "dtype": dtype,
    }
    if job.get("videoFaceCaptureEnc"):
        params["videoFaceCaptureEnc"] = job["videoFaceCaptureEnc"]
    if job.get("attDuration"):
        params["attDuration"] = job["attDuration"]
    if job.get("attDurationEnc"):
        params["attDurationEnc"] = job["attDurationEnc"]
    import re as _re
    rt = job.get("rt") or ""
    if not rt:
        m = _re.search(r"-rt_([1d])", job.get("otherinfo", ""))
        if m:
            rt = "0.9" if m.group(1) == "d" else "1"
    if rt:
        params["rt"] = rt
    params["_t"] = _ts()
    url = (f"https://mooc1.chaoxing.com/mooc-ans/multimedia/log/a/"
           f"{course['cpi']}/{dtoken}")
    try:
        resp = session.get(url, params=params, headers=headers, timeout=15)
    except requests.RequestException:
        return False, -1
    if resp.status_code == 200:
        try:
            return bool(resp.json().get("isPassed")), 200
        except Exception:
            return False, 200
    if resp.status_code == 403 and not _retried:
        # 403 风控: 刷新视频信息(dtoken)后重试一次
        info2 = get_video_info(session, course, job, dtype)
        if info2.get("status") == "success" and info2.get("dtoken") != dtoken:
            return video_progress_log(session, course, job, info2["dtoken"],
                                      int(info2.get("duration", duration)),
                                      playing_time, dtype, _retried=True)
    return False, resp.status_code


def study_video(session: requests.Session, course: dict, job: dict,
                speed: float = 1.0, dtype: str = "Video") -> str:
    """刷视频任务: 拉信息→立即双上报→按时间推进循环上报。返回结果"""
    info = get_video_info(session, course, job, dtype)
    if not info.get("status") == "success":
        return f"❌ 视频信息获取失败: {info.get('status')}"
    dtoken = info.get("dtoken", "")
    duration = int(info.get("duration", 0))
    play_time = int(job.get("playTime", 0)) // 1000
    if duration <= 0:
        return "❌ 视频时长为0/未知"
    passed, state = video_progress_log(session, course, job, dtoken,
                                       duration, play_time, dtype)
    passed, state = video_progress_log(session, course, job, dtoken,
                                       duration, duration, dtype)
    if passed:
        return f"✅ 完成 (瞬间): {job['name']}"
    last_log = 0
    wait = int(random.uniform(30, 90))
    last_iter = time.time()
    forbidden = 0
    while not passed:
        if play_time - last_log >= wait or play_time >= duration:
            passed, state = video_progress_log(session, course, job, dtoken,
                                               duration, play_time, dtype)
            if state == 403:
                forbidden += 1
                if forbidden >= 2:
                    st = course_status(session, course)
                    if st == "课程已结束":
                        return (f"⛔ 课程已结课, 学习上报被平台冻结(403), 无法刷课: "
                                f"{job['name']}")
                    return f"⚠️ 403风控重试失败, 跳过: {job['name']}"
                time.sleep(random.uniform(2, 4))
                info2 = get_video_info(session, course, job, dtype)
                if info2.get("status") == "success":
                    dtoken = info2.get("dtoken", dtoken)
                    duration = int(info2.get("duration", duration))
                    play_time = int(info2.get("playTime", play_time))
                continue
            elif not passed and state not in (200,):
                return f"❌ 上报异常(state={state}): {job['name']}"
            wait = int(random.uniform(30, 90))
            last_log = play_time
        dt = (time.time() - last_iter) * speed
        last_iter = time.time()
        play_time = min(duration, play_time + dt)
        time.sleep(1)
    return f"✅ 完成: {job['name']}"


def study_document(session: requests.Session, course: dict, job: dict,
                   knowledgeid: str) -> str:
    """刷文档任务: 一次请求即完成 (403自动重试一次)。"""
    import re as _re
    m = _re.search(r"nodeId_(.*?)-", job.get("otherinfo", ""))
    kid = m.group(1) if m else knowledgeid
    url = ("https://mooc1.chaoxing.com/ananas/job/document"
           f"?jobid={job['jobid']}&knowledgeid={kid}"
           f"&courseid={course['courseId']}&clazzid={course['clazzId']}"
           f"&jtoken={job.get('jtoken', '')}&_dc={_ts()}")
    for attempt in (1, 2):
        try:
            r = session.get(url, headers=HEADERS, timeout=20)
            if r.status_code == 200:
                return f"✅ 完成: {job['name']}"
            if r.status_code == 403 and attempt == 1:
                time.sleep(random.uniform(2, 4))
                continue
            return f"❌ HTTP {r.status_code}: {job['name']}"
        except requests.RequestException as e:
            return f"❌ {e}: {job['name']}"
    return f"❌ 重试失败: {job['name']}"


def study_read(session: requests.Session, course: dict, job: dict,
               knowledgeid: str) -> str:
    """刷阅读任务: 一次请求即完成 (403自动重试一次)。"""
    import re as _re
    m = _re.search(r"nodeId_(.*?)-", job.get("otherinfo", ""))
    kid = m.group(1) if m else knowledgeid
    url = ("https://mooc1.chaoxing.com/ananas/job/readv2"
           f"?jobid={job['jobid']}&knowledgeid={kid}"
           f"&jtoken={job.get('jtoken', '')}"
           f"&courseid={course['courseId']}&clazzid={course['clazzId']}")
    for attempt in (1, 2):
        try:
            r = session.get(url, headers=HEADERS, timeout=20)
            if r.status_code == 200:
                return f"✅ 完成: {job['name']}"
            if r.status_code == 403 and attempt == 1:
                time.sleep(random.uniform(2, 4))
                continue
            return f"❌ HTTP {r.status_code}: {job['name']}"
        except requests.RequestException as e:
            return f"❌ {e}: {job['name']}"
    return f"❌ 重试失败: {job['name']}"


def study_emptypage(session: requests.Session, course: dict,
                    knowledgeid: str) -> str:
    """刷空页面任务(studentstudyAjax)。"""
    params = {"courseId": course["courseId"], "clazzid": course["clazzId"],
              "chapterId": knowledgeid, "cpi": course["cpi"],
              "verificationcode": "", "mooc2": 1, "microTopicId": 0,
              "editorPreview": 0}
    try:
        r = session.get("https://mooc1.chaoxing.com/mooc-ans/mycourse/studentstudyAjax",
                        params=params, headers=HEADERS, timeout=20)
        return "✅ 完成(空任务)" if r.status_code == 200 else f"❌ HTTP {r.status_code}"
    except requests.RequestException as e:
        return f"❌ {e}"


def study_work(session: requests.Session, course: dict, job: dict,
               defaults: dict) -> str:
    """刷答题任务: 拉题→(外接/随机)选答案→提交。返回结果字符串。"""
    res = fetch_work_questions(session, course, job, defaults)
    if not res["status"]:
        return f"⚠️ {res['msg']}"
    questions = res["questions"]
    if not questions:
        return "⚠️ 未解析到题目, 跳过"
    print(f"  [作业] {job['name']} 共{len(questions)}题, 生成答案...")
    answer_data = dict(res["form_data"])
    for q in questions:
        ans = random_answer_for(q)
        qid = q["id"]
        answer_data[f"answer{qid}"] = ans
        answer_data[f"answertype{qid}"] = q["answertype"]
    try:
        resp = session.post("https://mooc1.chaoxing.com/mooc-ans/work/addStudentWorkNew",
                            data=answer_data, timeout=25,
                            headers={**HEADERS,
                                     "X-Requested-With": "XMLHttpRequest",
                                     "Accept": "application/json, text/javascript, */*; q=0.01",
                                     "Origin": "https://mooc1.chaoxing.com",
                                     "Referer": "https://mooc1.chaoxing.com/mooc-ans/work/doHomeWorkNew"})
        j = resp.json()
        if j.get("status"):
            return f"✅ 答题提交成功: {job['name']}"
        return f"⚠️ 提交失败: {j.get('msg')}"
    except Exception as e:
        return f"❌ 提交异常: {e}"


def fetch_work_questions(session: requests.Session, course: dict, job: dict,
                         defaults: dict) -> dict:
    """获取答题任务题目 (完整解析, 含字体解密 + 作业状态识别)。
    返回 {status, msg, form_data, questions:[{id,title,options,type,answertype}]}"""
    workid = job["jobid"].replace("work-", "")
    params = {
        "api": "1", "workId": workid, "jobid": job["jobid"],
        "originJobId": job["jobid"], "needRedirect": "true",
        "skipHeader": "true",
        "knowledgeid": str(defaults.get("knowledgeid", "")),
        "ktoken": defaults.get("ktoken", ""),
        "cpi": defaults.get("cpi", ""), "ut": "s",
        "clazzId": course["clazzId"], "type": "", "enc": job.get("enc", ""),
        "mooc2": "1", "courseid": course["courseId"],
    }
    try:
        r = session.get("https://mooc1.chaoxing.com/mooc-ans/api/work",
                        params=params, headers=HEADERS, timeout=25,
                        allow_redirects=True)
    except requests.RequestException as e:
        return {"status": False, "msg": f"拉题失败: {e}", "form_data": {},
                "questions": []}
    html = r.text
    # ---- 作业状态识别 (避免解析空壳页面抄歪) ----
    if "查看已批阅作业" in html or "selectWorkQuestionYiPiYue" in r.url:
        return {"status": False, "msg": "作业已批阅, 无法再次提交", "form_data": {},
                "questions": []}
    if "教师未创建完成" in html or "未创建完成" in html:
        return {"status": False, "msg": "教师未创建完成该测验, 跳过", "form_data": {},
                "questions": []}
    if "作业未开放" in html or "未开放" in html and "尚未开放" in html:
        return {"status": False, "msg": "作业未开放, 跳过", "form_data": {},
                "questions": []}
    if "考试已经结束" in html or "作业已经结束" in html:
        return {"status": False, "msg": "作业已结束, 跳过", "form_data": {},
                "questions": []}
    # ---- 字体解密 ----
    font_decoder = None
    if "cxSecretStyle" in html:
        try:
            from cxlib.font_decoder import FontDecoder
            font_decoder = FontDecoder(html)
        except Exception:
            font_decoder = None
        if not font_decoder or not getattr(font_decoder, "_FontDecoder__font_map", None):
            return {"status": False, "msg": "题目字体加密且解码失败, 跳过",
                    "form_data": {}, "questions": []}
    from bs4 import BeautifulSoup, NavigableString
    soup = BeautifulSoup(html, "lxml")
    # ---- 表单隐藏字段 (必须保留, 提交时一起带上) ----
    form_data = {}
    form = soup.find("form")
    if form:
        for inp in form.find_all("input"):
            n = inp.get("name")
            if n and "answer" not in n:
                form_data[n] = inp.get("value", "")
    else:
        # 无 form 时退而收集页面隐藏 input
        for inp in soup.find_all("input", type="hidden"):
            n = inp.get("name")
            if n and "answer" not in n:
                form_data[n] = inp.get("value", "")
    # ---- 题目解析 ----
    type_map = {"0": "single", "1": "multiple", "2": "completion",
                "3": "judgement", "4": "shortanswer"}
    questions = []
    # 优先新版容器 singleQuesId, 兜底 .TiMu
    qdivs = soup.select(".singleQuesId") or soup.select(".TiMu")
    for tm in qdivs:
        qdiv = tm if tm.get("class") and "singleQuesId" in tm.get("class") else (tm.parent if tm.parent else tm)
        # 题目id: singleQuesId 容器的 data; 题型码: 容器内 TiMu 的 data (参考项目)
        qid = qdiv.get("data", "") or tm.get("data", "")
        tm_inner = qdiv.select_one(".TiMu")
        tcode = tm_inner.get("data", "") if tm_inner else tm.get("data", "")
        if not tcode:
            tcode = qdiv.get("data", "")
        if not qid and not tcode:
            qid = tm.get("id", "") or ""
            tcode = tm.get("type", "") or ""
        qtype = type_map.get(tcode, "unknown")
        title_el = qdiv.select_one(".Zy_TItle") or tm.select_one(".Zy_TItle") or qdiv.select_one(".Zy_TItle p")
        title = ""
        if title_el:
            parts = []
            for item in title_el.descendants:
                if isinstance(item, NavigableString):
                    parts.append(item.string or "")
            title = "".join(parts)
            title = re.sub(r"[\r\t\n]", "", title).strip()
            if font_decoder:
                try:
                    title = font_decoder.decode(title)
                except Exception:
                    pass
        opts = []
        ul = qdiv.select_one("ul") or tm.select_one("ul")
        if ul:
            for li in ul.find_all("li"):
                t = li.get("aria-label") or li.get_text()
                if t:
                    t = re.sub(r"[\r\t\n]", "", t).strip()
                    if font_decoder:
                        try:
                            t = font_decoder.decode(t)
                        except Exception:
                            pass
                    t = t.strip()
                    if t.endswith("选择"):
                        t = t[:-2].rstrip()
                    if t:
                        opts.append(t)
        opts = sorted(set(opts))
        questions.append({"id": qid, "title": title, "options": opts,
                          "type": qtype, "answertype": tcode})
    # 无题目时给出页面提示
    if not questions:
        txt = re.sub(r"<[^>]+>", " ", html)
        txt = " ".join(txt.split())
        # 提取页面关键提示
        hint = ""
        for kw in ("教师未创建", "已提交", "未开放", "已结束", "已批阅", "暂无"):
            if kw in txt:
                hint = kw
                break
        return {"status": False,
                "msg": f"未解析到题目{hint and f'({hint})' or ''}", "form_data": {},
                "questions": []}
    # 组装提交必需的 answerwqbid (所有题目id, 参考项目)
    if questions:
        form_data["answerwqbid"] = ",".join(q["id"] for q in questions) + ","
    # pyFlag: 表单未提供时默认 "" (提交); "1"=仅保存
    form_data.setdefault("pyFlag", "")
    return {"status": True, "msg": "ok", "form_data": form_data,
            "questions": questions}



def random_answer_for(q: dict) -> str:
    """按题型生成随机答案 (参考 SuperStar_R random_answer)。"""
    opts = q.get("options") or []
    if q["type"] == "multiple":
        if not opts:
            return ""
        n = random.randint(2, min(4, len(opts))) if len(opts) > 2 else len(opts)
        return "".join(sorted(o[:1] for o in random.sample(opts, n)))
    if q["type"] == "single":
        return random.choice(opts)[:1] if opts else ""
    if q["type"] == "judgement":
        return random.choice(["true", "false"])
    return ""


def cmd_work(args) -> int:
    """获取课程的答题任务及题目列表。"""
    s = new_session(with_cookies=True)
    if not validate_session(s):
        print("[chaoxing] ❌ 未登录或 cookie 已失效 (运行 `chaoxing login`)")
        return 1
    course = _resolve_course(s, args.course)
    chapters = get_chapter_points(s, course)
    if args.chapter:
        if 1 <= args.chapter <= len(chapters):
            chapters = [chapters[args.chapter - 1]]
        else:
            print(f"[chaoxing] 章节序号越界(共{len(chapters)}章)")
            return 1
    total_work = 0
    for ch in chapters:
        for p in ch["points"]:
            kid = _strip_kid(p["id"])
            kj = get_knowledge_jobs(s, course, kid)
            defaults = kj.get("defaults", {})
            for job in kj.get("cards", []):
                if job["type"] != "workid":
                    continue
                total_work += 1
                res = fetch_work_questions(s, course, job, defaults)
                print(f"=== [作业] {job['name'] or job['jobid']} "
                      f"(jobid={job['jobid']}) ===")
                if not res["status"]:
                    print(f"   {res['msg']}")
                    continue
                for i, q in enumerate(res["questions"], 1):
                    print(f"  {i}. [{q['type']}] {q['title'][:60]}")
                    for o in q["options"]:
                        print(f"      {o[:50]}")
                print()
    if total_work == 0:
        print("[chaoxing] 该课程没有答题任务")
    return 0


def cmd_work_answer(args) -> int:
    """指定答案提交答题任务。--answers 格式: "1:A;2:B,C;3:true"。"""
    s = new_session(with_cookies=True)
    if not validate_session(s):
        print("[chaoxing] ❌ 未登录或 cookie 已失效 (运行 `chaoxing login`)")
        return 1
    course = _resolve_course(s, args.course)
    work_jobs = []
    chapters = get_chapter_points(s, course)
    for ch in chapters:
        for p in ch["points"]:
            kid = _strip_kid(p["id"])
            kj = get_knowledge_jobs(s, course, kid)
            for job in kj.get("cards", []):
                if job["type"] == "workid":
                    work_jobs.append({"chapter": ch["name"], "point": p["title"],
                                      "kid": kid, "job": job,
                                      "defaults": kj.get("defaults", {})})
    if not work_jobs:
        print("[chaoxing] 该课程没有答题任务")
        return 1
    target = None
    if args.work is None:
        print("[chaoxing] 选择答题任务:")
        for i, w in enumerate(work_jobs, 1):
            print(f"  {i}. [{w['chapter'][:12]}] {w['job']['name'] or w['job']['jobid']}")
        try:
            sel = input("请输入序号: ").strip()
        except EOFError:
            raise SystemExit("[chaoxing] 未选择")
        args.work = sel
    if str(args.work).isdigit() and 1 <= int(args.work) <= len(work_jobs):
        target = work_jobs[int(args.work) - 1]
    else:
        for w in work_jobs:
            if w["job"]["jobid"] == str(args.work):
                target = w
                break
    if not target:
        raise SystemExit(f"[chaoxing] 未找到答题任务: {args.work}")
    job = target["job"]
    defaults = target["defaults"]
    res = fetch_work_questions(s, course, job, defaults)
    if not res["status"] or not res["questions"]:
        print(f"[chaoxing] ❌ {res['msg']}")
        return 1
    answers = {}
    for part in args.answers.split(";"):
        if not part.strip():
            continue
        if ":" in part:
            k, v = part.split(":", 1)
        elif "=" in part:
            k, v = part.split("=", 1)
        else:
            continue
        answers[str(k).strip()] = v.strip()
    answer_data = dict(res["form_data"])
    for i, q in enumerate(res["questions"], 1):
        qid = q["id"]
        key = str(i)
        ans = answers.get(key, answers.get(str(qid), ""))
        if not ans and args.random_fill:
            ans = random_answer_for(q)
        answer_data[f"answer{qid}"] = ans
        answer_data[f"answertype{qid}"] = q["answertype"]
    try:
        resp = session.post("https://mooc1.chaoxing.com/mooc-ans/work/addStudentWorkNew",
                            data=answer_data, timeout=25,
                            headers={**HEADERS,
                                     "X-Requested-With": "XMLHttpRequest",
                                     "Accept": "application/json, text/javascript, */*; q=0.01",
                                     "Origin": "https://mooc1.chaoxing.com",
                                     "Referer": "https://mooc1.chaoxing.com/mooc-ans/work/doHomeWorkNew"})
        j = resp.json()
        if j.get("status"):
            print(f"[chaoxing] ✅ 提交成功: {j.get('msg')}")
            return 0
        print(f"[chaoxing] ❌ 提交失败: {j.get('msg')}")
        return 1
    except Exception as e:
        print(f"[chaoxing] ❌ 提交异常: {e}")
        return 1



def cmd_study(args) -> int:
    s = new_session(with_cookies=True)
    if not validate_session(s):
        print("[chaoxing] ❌ 未登录或 cookie 已失效 (运行 `chaoxing login`)")
        return 1
    course = _resolve_course(s, args.course)
    chapters = get_chapter_points(s, course)
    if args.chapter:
        if 1 <= args.chapter <= len(chapters):
            chapters = [chapters[args.chapter - 1]]
        else:
            print(f"[chaoxing] 章节序号越界(共{len(chapters)}章)")
            return 1
    want = set((args.type or "all").split(","))
    if "all" in want:
        want = {"video", "document", "read", "work", "emptypage"}
    print(f"[chaoxing] 开始刷课: 《{course['title']}》 速度x{args.speed} "
          f"类型={','.join(sorted(want))}\n")
    stats = {"done": 0, "skip": 0, "fail": 0}
    for ci, ch in enumerate(chapters, 1):
        print(f"[章节 {ci}/{len(chapters)}] {ch['name'].strip()}")
        for p in ch["points"]:
            kid = _strip_kid(p["id"])
            kj = get_knowledge_jobs(s, course, kid)
            defaults = kj.get("defaults", {})
            for job in kj.get("cards", []):
                jt = job["type"]
                if jt not in want:
                    continue
                if job["isPassed"]:
                    continue
                if jt in ("video", "audio"):
                    res = study_video(s, course, job, args.speed, jt)
                elif jt == "document":
                    res = study_document(s, course, job, kid)
                elif jt == "read":
                    res = study_read(s, course, job, kid)
                elif jt == "workid":
                    res = study_work(s, course, job, defaults)
                else:
                    continue
                mark = "✅" if res.startswith("✅") else ("⚠️" if res.startswith("⚠") else "❌")
                print(f"  {mark} {res}")
                if mark == "✅":
                    stats["done"] += 1
                elif mark == "⚠️":
                    stats["skip"] += 1
                else:
                    stats["fail"] += 1
            if not kj.get("cards") and "emptypage" in want:
                res = study_emptypage(s, course, kid)
                print(f"  {res}")
        print()
    print(f"[chaoxing] 刷课结束: 完成{stats['done']} 跳过{stats['skip']} 失败{stats['fail']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="chaoxing",
        description="超星学习通 CLI (登录/课程/章节/进度/任务点)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command")

    # login
    lp = sub.add_parser("login", help="登录 (账密/验证码/扫码)")
    lp.add_argument("-u", "--phone", help="手机号")
    lp.add_argument("-p", "--password", help="密码")
    lp.add_argument("--code", help="短信验证码")
    lp.add_argument("-q", "--qrcode", action="store_true", help="使用APP扫码登录")
    lp.add_argument("--fid", default="-1", help="机构ID (默认-1)")
    lp.add_argument("-f", "--force", action="store_true", help="忽略已有cookie强制重新登录")
    lp.add_argument("--timeout", type=int, default=None, help="扫码登录超时(秒)")
    lp.set_defaults(func=cmd_login)

    # status
    sp = sub.add_parser("status", help="查看登录状态")
    sp.set_defaults(func=cmd_status)

    # logout
    lout = sub.add_parser("logout", help="清除本地登录凭证")
    lout.set_defaults(func=cmd_logout)

    # courses
    cp = sub.add_parser("courses", help="获取课程列表(含课程ID/状态)")
    cp.add_argument("-j", "--json", action="store_true", help="以JSON输出")
    cp.add_argument("--ended", action="store_true", help="只看已结课课程")
    cp.add_argument("--status", help="按状态过滤(如: 已结束 / 进行中)")
    cp.set_defaults(func=cmd_courses)

    # chapters
    chap = sub.add_parser("chapters", help="列出某课程章节及任务点数量")
    chap.add_argument("-c", "--course", help="课程序号/courseId/课程名(留空交互选择)")
    chap.set_defaults(func=cmd_chapters)

    # progress
    prog = sub.add_parser("progress", help="刷课进度(每章已完成/总数百分比)")
    prog.add_argument("-c", "--course", help="课程序号/courseId/课程名(留空交互选择)")
    prog.add_argument("-a", "--all", action="store_true", help="显示全部课程进度")
    prog.set_defaults(func=cmd_progress)

    # jobs
    jp = sub.add_parser("jobs", help="查看某课程的章节任务点目录(视频/文档/答题等)")
    jp.add_argument("-c", "--course", help="课程序号/courseId/课程名(留空交互)")
    jp.add_argument("-p", "--point", type=int, default=None, help="只看第几章(1~n)")
    jp.add_argument("-j", "--json", action="store_true", help="JSON输出")
    jp.set_defaults(func=cmd_jobs)

    # whoami
    wp = sub.add_parser("whoami", help="查看当前登录用户信息")
    wp.set_defaults(func=cmd_whoami)

    # discuss
    dp = sub.add_parser("discuss", help="思考讨论话题列表(红绿点完成状态)")
    dp.add_argument("-c", "--course", help="课程序号/courseId/课程名(留空交互)")
    dp.add_argument("-p", "--point", type=int, default=None, help="只看第几章")
    dp.set_defaults(func=cmd_discuss)

    dpr = sub.add_parser("discuss-reply", help="在思考讨论话题下发表回复(完成任务)")
    dpr.add_argument("-c", "--course", help="课程序号/courseId/课程名(留空交互)")
    dpr.add_argument("-t", "--topic", help="话题序号/mid/uuid(留空交互)")
    dpr.add_argument("--content", required=True, help="回复内容")
    dpr.add_argument("--anonymous", action="store_true", help="匿名回复(不计成绩)")
    dpr.set_defaults(func=cmd_discuss_reply)

    dpl = sub.add_parser("discuss-replies", help="查看话题回复列表")
    dpl.add_argument("-c", "--course", help="课程序号/courseId/课程名(留空交互)")
    dpl.add_argument("-t", "--topic", help="话题序号/mid/uuid(留空交互)")
    dpl.add_argument("--pages", type=int, default=3, help="拉取页数(默认3)")
    dpl.set_defaults(func=cmd_discuss_replies)

    dpd = sub.add_parser("discuss-delete", help="删除自己的讨论回复")
    dpd.add_argument("-c", "--course", help="课程序号/courseId/课程名(留空交互)")
    dpd.add_argument("-t", "--topic", help="话题序号/mid/uuid(留空交互)")
    dpd.add_argument("-r", "--reply", help="回复uuid(留空自动列出我的回复)")
    dpd.add_argument("--pages", type=int, default=3, help="查找页数(默认3)")
    dpd.set_defaults(func=cmd_discuss_delete)

    # study
    sp2 = sub.add_parser("study", help="刷课: 自动完成视频/文档/阅读/答题任务")
    sp2.add_argument("-c", "--course", help="课程序号/courseId/课程名(留空交互)")
    sp2.add_argument("--chapter", type=int, default=None, help="只刷第几章")
    sp2.add_argument("--type", default="all",
                     help="任务类型: all/video/document/read/work(逗号分隔, 默认all)")
    sp2.add_argument("--speed", type=float, default=2.0, help="视频倍速(默认2, 最大2)")
    sp2.set_defaults(func=cmd_study)

    # work
    wp2 = sub.add_parser("work", help="获取答题任务题目列表(含字体解密)")
    wp2.add_argument("-c", "--course", help="课程序号/courseId/课程名(留空交互)")
    wp2.add_argument("--chapter", type=int, default=None, help="只看第几章")
    wp2.set_defaults(func=cmd_work)

    # work-answer
    wa = sub.add_parser("work-answer", help="指定答案提交答题任务")
    wa.add_argument("-c", "--course", help="课程序号/courseId/课程名(留空交互)")
    wa.add_argument("-w", "--work", help="答题任务序号或jobid(留空交互)")
    wa.add_argument("--answers", required=True,
                    help='答案: "1:A;2:B,C;3:true" (题号:答案, 分号分隔)')
    wa.add_argument("--random-fill", action="store_true",
                    help="未指定的题目用随机答案填充")
    wa.set_defaults(func=cmd_work_answer)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
