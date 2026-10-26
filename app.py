import os, re, sqlite3, time, secrets, json, urllib.request
from functools import wraps
from flask import Flask, request, jsonify, g, Response
from werkzeug.security import generate_password_hash, check_password_hash

ADMIN = os.environ.get("ADMIN_EMAIL", "umarat239@gmail.com").lower()
DB = os.environ.get("DB_PATH", "klepa.db")
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 14 * 1024 * 1024
SUP = 1  # id официальной поддержки

SCHEMA = """
create table if not exists users(id integer primary key, email text unique, username text unique, name text, pw text,
 avatar text default '', banner text default '', bio text default '', seen real default 0, is_admin int default 0,
 banned int default 0, chatban int default 0, verified int default 0, official int default 0, created real);
create table if not exists codes(email text, kind text, code text, exp real);
create table if not exists tokens(token text primary key, uid int);
create table if not exists chats(id integer primary key, a int, b int, unique(a,b));
create table if not exists msgs(id integer primary key, chat int, sender int, text text, media text default '', ts real);
create table if not exists blocks(a int, b int, primary key(a,b));
create table if not exists reports(id integer primary key, uid int, target int, reason text, text text, ts real);
create table if not exists blacklist(email text primary key);
"""


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB, timeout=15)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close(_):
    d = g.pop("db", None)
    if d:
        d.close()


def q(sql, a=(), one=False):
    r = db().execute(sql, a).fetchall()
    return (r[0] if r else None) if one else r


def run(sql, a=()):
    c = db().execute(sql, a)
    db().commit()
    return c.lastrowid


with app.app_context():
    db().executescript(SCHEMA)
    if not q("select 1 from users where id=?", (SUP,), True):
        run("insert into users(id,email,username,name,pw,verified,official,created) values(?,?,?,?,?,1,1,?)",
            (SUP, "support@klepa.local", "klepa_support", "Klepa Support", "!", time.time()))


def send_mail(to, code, subj):
    key = os.environ.get("BREVO_API_KEY")
    if not key:
        print("CODE", to, code, flush=True)  # без ключа код пишется в логи Render
        return
    body = json.dumps({"sender": {"email": os.environ["MAIL_FROM"], "name": "Klepa Mess"}, "to": [{"email": to}],
                       "subject": subj, "textContent": f"Ваш код: {code}\nОн действует 10 минут."}).encode()
    req = urllib.request.Request("https://api.brevo.com/v3/smtp/email", body,
                                 {"api-key": key, "content-type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print("mail error", e, flush=True)


def new_code(email, kind):
    c = f"{secrets.randbelow(10**6):06d}"
    run("delete from codes where email=? and kind=?", (email, kind))
    run("insert into codes values(?,?,?,?)", (email, kind, c, time.time() + 600))
    send_mail(email, c, "Код Klepa Mess")


def check_code(email, kind, code):
    r = q("select * from codes where email=? and kind=?", (email, kind), True)
    ok = r and r["code"] == str(code).strip() and r["exp"] > time.time()
    if ok:
        run("delete from codes where email=? and kind=?", (email, kind))
    return bool(ok)


def err(m, c=400):
    return jsonify(error=m), c


def auth(admin=False):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            t = request.headers.get("Authorization", "")[7:]
            r = q("select u.* from tokens t join users u on u.id=t.uid where t.token=?", (t,), True)
            if not r or r["banned"]:
                return err("auth", 401)
            if admin and not r["is_admin"]:
                return err("Нет доступа", 403)
            g.u = r
            run("update users set seen=? where id=?", (time.time(), r["id"]))
            return f(*a, **k)
        return w
    return deco


def pub(u, full=False):
    d = dict(id=u["id"], name=u["name"], username=u["username"], avatar=u["avatar"],
             official=u["official"], online=(time.time() - u["seen"] < 45), seen=u["seen"])
    if full:
        d.update(bio=u["bio"], banner=u["banner"])
    return d


def chat_id(x, y):
    a, b = min(x, y), max(x, y)
    r = q("select id from chats where a=? and b=?", (a, b), True)
    return r["id"] if r else run("insert into chats(a,b) values(?,?)", (a, b))


def say(chat, sender, text, media=""):
    return run("insert into msgs(chat,sender,text,media,ts) values(?,?,?,?,?)", (chat, sender, text, media, time.time()))


def support_hello(uid):
    c = chat_id(SUP, uid)
    if not q("select 1 from msgs where chat=?", (c,), True):
        say(c, SUP, "Здравствуйте! Я официальная поддержка Klepa Mess. Выберите тему обращения:",
            "opts:Жалоба на пользователя|Ошибка в приложении|Вопрос по аккаунту|Другое")


def session(uid):
    t = secrets.token_urlsafe(32)
    run("insert into tokens values(?,?)", (t, uid))
    return t


def valid_user(u):
    return bool(re.fullmatch(r"[a-z0-9_]{4,20}", u or ""))


@app.get("/")
def index():
    return Response(PAGE, mimetype="text/html")


@app.get("/api/username")
def uname():
    u = (request.args.get("u") or "").lower()
    if not valid_user(u):
        return jsonify(ok=False, why="4–20 символов: a–z, 0–9, _")
    return jsonify(ok=not q("select 1 from users where username=? and verified=1", (u,), True), why="Занято")


@app.get("/api/config")
def config():
    return jsonify(mail=bool(os.environ.get("BREVO_API_KEY")))


@app.post("/api/register")
def register():
    d = request.json or {}
    em, pw, un, nm = (d.get("email") or "").strip().lower(), d.get("password") or "", (d.get("username") or "").lower(), (d.get("name") or "").strip()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", em):
        return err("Неверная почта")
    if len(pw) < 6:
        return err("Пароль: минимум 6 символов")
    if not nm or not valid_user(un):
        return err("Заполните имя и юзернейм")
    if q("select 1 from blacklist where email=?", (em,), True):
        return err("Регистрация с этой почты запрещена", 403)
    if q("select 1 from users where email=? and verified=1", (em,), True):
        return err("Почта уже занята")
    if q("select 1 from users where username=? and verified=1 and email!=?", (un, em), True):
        return err("Юзернейм занят")
    run("delete from users where email=? and verified=0", (em,))
    run("delete from users where username=? and verified=0", (un,))
    uid = run("insert into users(email,username,name,pw,is_admin,verified,created) values(?,?,?,?,?,1,?)",
              (em, un, nm, generate_password_hash(pw), 1 if em == ADMIN else 0, time.time()))
    support_hello(uid)
    return jsonify(token=session(uid))


@app.post("/api/login")
def login():
    d = request.json or {}
    em = (d.get("email") or "").strip().lower()
    u = q("select * from users where email=?", (em,), True)
    if not u or not check_password_hash(u["pw"], d.get("password") or ""):
        return err("Неверная почта или пароль")
    if u["banned"]:
        return err("Аккаунт заблокирован", 403)
    if not u["verified"]:
        run("update users set verified=1 where id=?", (u["id"],))
        support_hello(u["id"])
    return jsonify(token=session(u["id"]))


@app.post("/api/forgot")
def forgot():
    if not os.environ.get("BREVO_API_KEY"):
        return err("Восстановление пароля пока недоступно")
    em = ((request.json or {}).get("email") or "").strip().lower()
    if q("select 1 from users where email=? and verified=1", (em,), True):
        new_code(em, "reset")
    return jsonify(ok=True)  # не раскрываем, есть ли такая почта


@app.post("/api/reset")
def reset():
    d = request.json or {}
    em = (d.get("email") or "").strip().lower()
    if len(d.get("password") or "") < 6:
        return err("Пароль: минимум 6 символов")
    if not check_code(em, "reset", d.get("code")):
        return err("Неверный или просроченный код")
    u = q("select id from users where email=?", (em,), True)
    run("update users set pw=? where email=?", (generate_password_hash(d["password"]), em))
    run("delete from tokens where uid=?", (u["id"],))
    return jsonify(token=session(u["id"]))


@app.get("/api/me")
@auth()
def me():
    u = g.u
    return jsonify(**pub(u, True), email=u["email"], is_admin=u["is_admin"])


@app.post("/api/me")
@auth()
def me_edit():
    d, u = request.json or {}, g.u
    nm, un = (d.get("name") or u["name"]).strip(), (d.get("username") or u["username"]).lower()
    if not nm:
        return err("Имя не может быть пустым")
    if not valid_user(un):
        return err("Юзернейм: 4–20 символов a–z, 0–9, _")
    if q("select 1 from users where username=? and id!=?", (un, u["id"]), True):
        return err("Юзернейм занят")
    run("update users set name=?,username=?,bio=?,avatar=?,banner=? where id=?",
        (nm[:40], un, (d.get("bio") or "")[:200], d.get("avatar", u["avatar"]), d.get("banner", u["banner"]), u["id"]))
    return jsonify(ok=True)


@app.get("/api/search")
@auth()
def search():
    s = (request.args.get("q") or "").strip().lower().lstrip("@")
    if not s:
        return jsonify([])
    r = q("select * from users where verified=1 and banned=0 and id!=? and (username like ? or lower(name) like ?) limit 20",
          (g.u["id"], s + "%", "%" + s + "%"))
    return jsonify([pub(u) for u in r])


@app.get("/api/user/<int:uid>")
@auth()
def user(uid):
    u = q("select * from users where id=? and verified=1", (uid,), True)
    if not u:
        return err("Не найден", 404)
    return jsonify(**pub(u, True), blocked=bool(q("select 1 from blocks where a=? and b=?", (g.u["id"], uid), True)))


@app.get("/api/chats")
@auth()
def chats():
    me_ = g.u["id"]
    out = []
    for c in q("select * from chats where a=? or b=?", (me_, me_)):
        pid = c["b"] if c["a"] == me_ else c["a"]
        last = q("select * from msgs where chat=? order by id desc limit 1", (c["id"],), True)
        if not last:
            continue
        p = q("select * from users where id=?", (pid,), True)
        out.append(dict(id=c["id"], peer=pub(p), ts=last["ts"], last=last["text"] or ("Фото" if last["media"].startswith("img:") else ""),
                        mine=last["sender"] == me_))
    out.sort(key=lambda x: -x["ts"])
    return jsonify(out)


@app.post("/api/chats")
@auth()
def chat_new():
    pid = int((request.json or {}).get("peer", 0))
    p = q("select * from users where id=? and verified=1", (pid,), True)
    if not p or pid == g.u["id"]:
        return err("Пользователь не найден")
    c = chat_id(g.u["id"], pid)
    if g.u["chatban"] and pid != SUP and not q("select 1 from msgs where chat=? and sender=?", (c, pid), True):
        return err("Вам ограничена отправка новым пользователям", 403)
    return jsonify(id=c, peer=pub(p))


def mine(cid):
    c = q("select * from chats where id=?", (cid,), True)
    return c if c and g.u["id"] in (c["a"], c["b"]) else None


@app.get("/api/msgs/<int:cid>")
@auth()
def msgs(cid):
    if not mine(cid):
        return err("Нет доступа", 403)
    after = int(request.args.get("after", 0))
    if after:
        r = q("select * from msgs where chat=? and id>? order by id limit 200", (cid, after))
    else:
        r = q("select * from (select * from msgs where chat=? order by id desc limit 100) order by id", (cid,))
    return jsonify([dict(r_) for r_ in r])


@app.post("/api/msgs/<int:cid>")
@auth()
def send(cid):
    c, d = mine(cid), request.json or {}
    if not c:
        return err("Нет доступа", 403)
    text, media = (d.get("text") or "").strip()[:4000], d.get("media") or ""
    if not text and not media:
        return err("Пустое сообщение")
    pid = c["b"] if c["a"] == g.u["id"] else c["a"]
    if pid != SUP:
        if q("select 1 from blocks where (a=? and b=?) or (a=? and b=?)", (g.u["id"], pid, pid, g.u["id"]), True):
            return err("Нельзя написать этому пользователю", 403)
        if g.u["chatban"] and not q("select 1 from msgs where chat=? and sender=?", (cid, pid), True):
            return err("Вам ограничена отправка новым пользователям", 403)
    mid = say(cid, g.u["id"], text, media if media.startswith("img:") and len(media) < 13_000_000 else "")
    if pid == SUP and text.startswith("Тема: "):
        say(cid, SUP, "Опишите проблему одним сообщением — оно сразу попадёт к администратору.")
    return jsonify(id=mid)


@app.post("/api/block")
@auth()
def block():
    pid = int((request.json or {}).get("peer", 0))
    if q("select 1 from blocks where a=? and b=?", (g.u["id"], pid), True):
        run("delete from blocks where a=? and b=?", (g.u["id"], pid))
        return jsonify(blocked=False)
    run("insert into blocks values(?,?)", (g.u["id"], pid))
    return jsonify(blocked=True)


@app.post("/api/report")
@auth()
def report():
    d = request.json or {}
    run("insert into reports(uid,target,reason,text,ts) values(?,?,?,?,?)",
        (g.u["id"], int(d.get("target", 0)), (d.get("reason") or "")[:60], (d.get("text") or "")[:1000], time.time()))
    return jsonify(ok=True)


# ---------- админ ----------
@app.get("/api/admin/stats")
@auth(True)
def a_stats():
    n = time.time()
    return jsonify(users=q("select count(*) c from users where verified=1 and id!=?", (SUP,), True)["c"],
                   online=q("select count(*) c from users where seen>? and id!=?", (n - 45, SUP), True)["c"],
                   today=q("select count(*) c from users where created>? and verified=1", (n - 86400,), True)["c"],
                   msgs=q("select count(*) c from msgs", (), True)["c"],
                   reports=q("select count(*) c from reports", (), True)["c"])


@app.get("/api/admin/users")
@auth(True)
def a_users():
    s = "%" + (request.args.get("q") or "").lower() + "%"
    r = q("select * from users where verified=1 and id!=? and (lower(email) like ? or username like ? or lower(name) like ?) order by id desc limit 100",
          (SUP, s, s, s))
    return jsonify([dict(pub(u), email=u["email"], banned=u["banned"], chatban=u["chatban"], is_admin=u["is_admin"]) for u in r])


@app.get("/api/admin/user/<int:uid>/chats")
@auth(True)
def a_chats(uid):
    out = []
    for c in q("select * from chats where a=? or b=?", (uid, uid)):
        pid = c["b"] if c["a"] == uid else c["a"]
        last = q("select * from msgs where chat=? order by id desc limit 1", (c["id"],), True)
        if last:
            out.append(dict(id=c["id"], peer=pub(q("select * from users where id=?", (pid,), True)), last=last["text"] or "Медиа", ts=last["ts"]))
    return jsonify(sorted(out, key=lambda x: -x["ts"]))


@app.get("/api/admin/chat/<int:cid>")
@auth(True)
def a_chat(cid):
    r = q("select m.*,u.name from msgs m join users u on u.id=m.sender where m.chat=? order by m.id desc limit 200", (cid,))
    return jsonify([dict(x) for x in reversed(r)])


@app.post("/api/admin/act")
@auth(True)
def a_act():
    d = request.json or {}
    uid, act = int(d.get("uid", 0)), d.get("act")
    u = q("select * from users where id=?", (uid,), True)
    if not u or u["is_admin"] or uid == SUP:
        return err("Недоступно")
    if act in ("delete", "blacklist"):
        if act == "blacklist":
            run("insert or ignore into blacklist values(?)", (u["email"],))
        for c in q("select id from chats where a=? or b=?", (uid, uid)):
            run("delete from msgs where chat=?", (c["id"],))
        run("delete from chats where a=? or b=?", (uid, uid))
        run("delete from tokens where uid=?", (uid,))
        run("delete from users where id=?", (uid,))
    elif act in ("chatban", "unchatban"):
        run("update users set chatban=? where id=?", (1 if act == "chatban" else 0, uid))
        say(chat_id(SUP, uid), SUP, "Вам выдан бан чата: вы не можете писать новым пользователям." if act == "chatban"
            else "Бан чата снят. Вы снова можете писать новым пользователям.")
    elif act in ("ban", "unban"):
        run("update users set banned=? where id=?", (1 if act == "ban" else 0, uid))
        if act == "ban":
            run("delete from tokens where uid=?", (uid,))
    return jsonify(ok=True)


@app.get("/api/admin/reports")
@auth(True)
def a_reports():
    r = q("""select r.*,a.name an,a.username au,b.name bn,b.username bu from reports r
             left join users a on a.id=r.uid left join users b on b.id=r.target order by r.id desc limit 100""")
    return jsonify([dict(x) for x in r])


@app.get("/api/admin/support")
@auth(True)
def a_support():
    out = []
    for c in q("select * from chats where a=?", (SUP,)):
        last = q("select * from msgs where chat=? order by id desc limit 1", (c["id"],), True)
        u = q("select * from users where id=?", (c["b"],), True)
        if last and u:
            out.append(dict(uid=u["id"], chat=c["id"], user=pub(u), last=last["text"], ts=last["ts"], waiting=last["sender"] != SUP))
    return jsonify(sorted(out, key=lambda x: (not x["waiting"], -x["ts"])))


@app.post("/api/admin/support")
@auth(True)
def a_reply():
    d = request.json or {}
    t = (d.get("text") or "").strip()
    if t:
        say(chat_id(SUP, int(d.get("uid", 0))), SUP, t)
    return jsonify(ok=True)




PAGE = r"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Klepa Mess</title>
<style>
:root{--bg1:#dce8ff;--bg2:#f6e4ff;--g:rgba(255,255,255,.52);--gb:rgba(255,255,255,.75);--t:#13151f;--t2:#6a7182;--ac:#2f7bff;--in:rgba(255,255,255,.65);--th:rgba(255,255,255,.85);--sh:rgba(40,60,120,.14)}
[data-t=dark]{--bg1:#0b0e1c;--bg2:#1a1030;--g:rgba(34,38,62,.55);--gb:rgba(255,255,255,.13);--t:#f1f3fb;--t2:#99a2b8;--in:rgba(255,255,255,.08);--th:rgba(70,76,110,.85);--sh:rgba(0,0,0,.4)}
*{box-sizing:border-box;margin:0;-webkit-tap-highlight-color:transparent}
body{font:15px/1.4 -apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",Roboto,sans-serif;color:var(--t);background:linear-gradient(135deg,var(--bg1),var(--bg2));height:100dvh;overflow:hidden}
body:before{content:"";position:fixed;inset:0;z-index:-1;background:radial-gradient(circle at 12% 18%,rgba(100,150,255,.4),transparent 42%),radial-gradient(circle at 88% 82%,rgba(255,140,220,.32),transparent 42%)}
button,input,textarea,select{font:inherit;color:inherit;border:0;outline:0;background:none}
.gl,nav,.list,.chat,.box,.modal>div{background:var(--g);backdrop-filter:blur(30px) saturate(190%);-webkit-backdrop-filter:blur(30px) saturate(190%);border:1px solid var(--gb);box-shadow:0 10px 36px var(--sh),inset 0 1px 0 rgba(255,255,255,.45)}
.app{display:flex;gap:12px;padding:12px;height:100dvh}
nav{width:78px;border-radius:30px;display:flex;flex-direction:column;align-items:center;gap:8px;padding:16px 0}
nav button{width:54px;height:54px;border-radius:20px;display:grid;place-items:center;color:var(--t2);position:relative;transition:.2s}
nav button.on{background:var(--ac);color:#fff;box-shadow:0 6px 18px rgba(47,123,255,.45)}
nav span{display:none}
.list{width:370px;border-radius:30px;overflow:auto;padding:18px 14px}
.chat{flex:1;border-radius:30px;display:flex;flex-direction:column;overflow:hidden;min-width:0}
.page .list{flex:1;width:auto}.page .chat{display:none}
.pg{max-width:720px;margin:0 auto}
h1{font-size:28px;font-weight:700;letter-spacing:-.5px;margin:2px 6px 14px}
h3{margin:18px 6px 8px;font-size:15px}
.row{display:flex;align-items:center;gap:12px;padding:10px;border-radius:20px;cursor:pointer;transition:.15s}
.row:hover{background:var(--in)}
.row .tx{flex:1;min-width:0}.row b{display:flex;align-items:center;gap:5px}
.row small,.sm{color:var(--t2);font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block}
.av{width:48px;height:48px;border-radius:50%;flex:none;background:linear-gradient(135deg,#6aa5ff,#c47bff);color:#fff;display:grid;place-items:center;font-weight:700;overflow:hidden;position:relative}
.av img{width:100%;height:100%;object-fit:cover}
.on_{position:absolute;right:0;bottom:0;width:13px;height:13px;border-radius:50%;background:#34c759;border:2px solid #fff}
.chk{width:16px;height:16px;flex:none}
input.f,textarea.f,select.f{display:block;width:100%;padding:14px 16px;border-radius:18px;background:var(--in);border:1px solid var(--gb);margin-bottom:10px}
.pri{width:100%;padding:14px;border-radius:18px;background:var(--ac);color:#fff;font-weight:600;box-shadow:0 8px 22px rgba(47,123,255,.4)}
.sec{padding:12px 16px;border-radius:16px;background:var(--in);border:1px solid var(--gb)}
.dng{color:#ff453a}
.hint{font-size:13px;margin:-4px 6px 10px;min-height:16px;color:var(--t2)}.hint.bad{color:#ff453a}.hint.ok{color:#34c759}
.lk{text-align:center;margin-top:14px;color:var(--t2)}.lk a{color:var(--ac);cursor:pointer}
.authw{height:100dvh;display:grid;place-items:center;padding:16px}
.box{width:100%;max-width:400px;border-radius:34px;padding:30px 24px}
.box h1{text-align:center;margin-bottom:4px}.box .sm{text-align:center;margin-bottom:20px;white-space:normal}
.ch-h{display:flex;align-items:center;gap:12px;padding:14px 18px;border-bottom:1px solid var(--gb);cursor:pointer}
.ch-h .av{width:42px;height:42px}
.back{display:none;color:var(--ac)}
#M{flex:1;overflow:auto;padding:16px;display:flex;flex-direction:column;gap:6px}
.m{max-width:min(75%,520px);padding:9px 13px;border-radius:20px 20px 20px 6px;background:var(--th);align-self:flex-start;word-wrap:break-word;white-space:pre-wrap}
.m.me{align-self:flex-end;background:var(--ac);color:#fff;border-radius:20px 20px 6px 20px}
.m img{max-width:100%;border-radius:14px;display:block;margin-bottom:4px}
.m time{display:block;font-size:11px;opacity:.6;text-align:right}
.opts{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}.opts button{padding:8px 12px;border-radius:14px;background:var(--in);border:1px solid var(--gb)}
.comp{display:flex;gap:8px;padding:12px;align-items:flex-end}
.comp textarea{flex:1;max-height:120px;padding:12px 16px;border-radius:22px;background:var(--in);border:1px solid var(--gb);resize:none}
.ib{width:46px;height:46px;border-radius:50%;display:grid;place-items:center;flex:none;color:var(--t2);cursor:pointer}
.ib.p{background:var(--ac);color:#fff}
.empty{margin:auto;color:var(--t2);text-align:center;padding:30px}
.ban{height:130px;border-radius:24px;background:linear-gradient(135deg,#6aa5ff,#c47bff) center/cover;position:relative;cursor:pointer}
.big{width:92px;height:92px;border:4px solid var(--bg1);margin:-46px 0 0 20px;cursor:pointer}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.stats div{padding:16px;border-radius:22px;background:var(--in);border:1px solid var(--gb)}.stats b{display:block;font-size:26px}
.tabs{display:flex;gap:6px;margin:16px 0 10px}.tabs button{flex:1;padding:10px;border-radius:16px;color:var(--t2)}.tabs .on{background:var(--ac);color:#fff}
.acts{display:flex;gap:6px;flex-wrap:wrap;margin:0 10px 8px 70px}.acts button{padding:6px 11px;border-radius:12px;background:var(--in);border:1px solid var(--gb);font-size:13px}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.35);display:grid;place-items:center;padding:16px;z-index:50;overflow:auto}
.modal>div{width:100%;max-width:440px;border-radius:30px;padding:20px;max-height:90dvh;overflow:auto;background:var(--g)}
.tg{width:52px;height:32px;border-radius:16px;background:var(--in);border:1px solid var(--gb);position:relative}.tg:after{content:"";position:absolute;top:3px;left:3px;width:24px;height:24px;border-radius:50%;background:#fff;transition:.2s}[data-t=dark] .tg{background:var(--ac)}[data-t=dark] .tg:after{left:23px}
.toast{position:fixed;top:16px;left:50%;transform:translateX(-50%);padding:12px 18px;border-radius:18px;z-index:99;background:#222;color:#fff;max-width:90%}
@media(max-width:800px){
.app{padding:8px 8px 0;gap:0}
nav{position:fixed;left:12px;right:12px;bottom:calc(10px + env(safe-area-inset-bottom));width:auto;height:68px;flex-direction:row;justify-content:space-around;padding:7px;z-index:5;border-radius:34px}
nav button{width:auto;flex:1;height:100%;border-radius:26px}
.list{width:auto;flex:1;padding-bottom:100px;border-radius:26px}
.chat{display:none;border-radius:26px;margin-bottom:8px}
.open .list,.open nav{display:none}.open .chat{display:flex}
.back{display:block}.m{max-width:85%}.acts{margin-left:10px}
}
</style></head>
<body><div id="root"></div>
<script>
const $=s=>document.querySelector(s),R=$('#root');
const E=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const I={chat:'M21 12a8 8 0 0 1-11.6 7.1L3 21l1.9-6A8 8 0 1 1 21 12z',search:'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM21 21l-4.3-4.3',user:'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8z',shield:'M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5z',send:'M22 2L11 13M22 2l-7 20-4-9-9-4z',back:'M15 18l-6-6 6-6',img:'M3 5h18v14H3zM8.5 10a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3zM21 15l-5-5L5 19'};
const ic=(n,s=24)=>`<svg width=${s} height=${s} viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=1.9 stroke-linecap=round stroke-linejoin=round><path d="${I[n]}"/></svg>`;
const CHK='<svg class=chk viewBox="0 0 24 24"><circle cx=12 cy=12 r=11 fill="#2f7bff"/><path d="M7 12.5l3.2 3.2L17 9" stroke=#fff stroke-width=2.4 fill=none stroke-linecap=round stroke-linejoin=round /></svg>';
let S={tok:localStorage.k,tab:'chats',cur:null,mode:'login',em:'',msgs:[],at:'users'};
document.documentElement.dataset.t=localStorage.t||'';
function toast(m){const t=document.createElement('div');t.className='toast';t.textContent=m;document.body.appendChild(t);setTimeout(()=>t.remove(),3200)}
async function api(p,b){const r=await fetch('/api/'+p,{method:b?'POST':'GET',headers:{'Content-Type':'application/json',Authorization:'Bearer '+S.tok},body:b?JSON.stringify(b):undefined});const j=await r.json().catch(()=>({}));if(r.status==401&&S.tok){localStorage.removeItem('k');S.tok=0;boot();throw''}if(!r.ok){toast(j.error||'Ошибка');throw j.error}return j}
const av=(u,s)=>`<div class=av ${s?`style="width:${s}px;height:${s}px"`:''}>${u.avatar?`<img src="${E(u.avatar)}">`:E((u.name||'?')[0].toUpperCase())}${u.online&&!u.official?'<i class=on_></i>':''}</div>`;
const nm=u=>`${E(u.name)}${u.official?CHK:''}`;
const hm=t=>new Date(t*1e3).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
const dt=t=>{const d=new Date(t*1e3);return d.toDateString()==new Date().toDateString()?hm(t):d.toLocaleDateString([], {day:'numeric',month:'short'})+' '+hm(t)};
const stat=u=>u.official?'официальная поддержка':u.online?'в сети':'был(а) '+dt(u.seen);
function shrink(f,w,cb){const r=new FileReader();r.onload=()=>{const i=new Image();i.onload=()=>{const k=Math.min(1,w/i.width),c=document.createElement('canvas');c.width=i.width*k;c.height=i.height*k;c.getContext('2d').drawImage(i,0,0,c.width,c.height);cb(c.toDataURL('image/jpeg',.82))};i.src=r.result};r.readAsDataURL(f)}
function pick(w,cb){const i=document.createElement('input');i.type='file';i.accept='image/*';i.onchange=()=>i.files[0]&&shrink(i.files[0],w,cb);i.click()}
function modal(h){const m=document.createElement('div');m.className='modal';m.innerHTML=`<div>${h}</div>`;m.onclick=e=>{if(e.target==m)m.remove()};document.body.appendChild(m);return m}
const v=id=>$('#'+id).value.trim();

/* ---------- вход ---------- */
function auth(){const m=S.mode,f=(id,p,t='text',x='')=>`<input class=f id=${id} placeholder="${p}" type=${t} ${x}>`;
const T={login:['Klepa Mess','Войдите в аккаунт',f('em','Почта','email')+f('pw','Пароль','password')+'<button class=pri onclick=login()>Войти</button><p class=lk><a onclick=md("register")>Регистрация</a>'+(S.mail?' · <a onclick=md("forgot")>Забыли пароль?</a>':'')+'</p>'],
register:['Регистрация','Создайте аккаунт за минуту',f('nm','Имя')+f('un','Юзернейм (a–z, 0–9, _)','text','oninput=chkU(this.value)')+'<div class=hint id=uh></div>'+f('em','Почта','email')+f('pw','Пароль (от 6 символов)','password')+'<button class=pri onclick=reg()>Создать аккаунт</button><p class=lk><a onclick=md("login")>Уже есть аккаунт</a></p>'],
forgot:['Восстановление','Отправим код на вашу почту',f('em','Почта','email')+'<button class=pri onclick=fg()>Отправить код</button><p class=lk><a onclick=md("login")>Назад</a></p>'],
reset:['Новый пароль','Код отправлен на '+E(S.em),f('cd','Код из письма','text','inputmode=numeric maxlength=6')+f('pw','Новый пароль','password')+'<button class=pri onclick=rs()>Сохранить</button>']}[m];
R.innerHTML=`<div class=authw><div class=box><h1>${T[0]}</h1><p class=sm>${T[1]}</p>${T[2]}</div></div>`;if($('#em')&&S.em)$('#em').value=S.em}
const md=m=>{S.mode=m;auth()};let ut;
function chkU(x){clearTimeout(ut);const h=$('#uh');ut=setTimeout(async()=>{if(!x)return h.textContent='';const r=await(await fetch('/api/username?u='+encodeURIComponent(x))).json();h.className='hint '+(r.ok?'ok':'bad');h.textContent=r.ok?'Свободно':r.why},250)}
const post=(p,b)=>fetch('/api/'+p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}).then(async r=>{const j=await r.json();if(!r.ok){toast(j.error);throw 0}return j});
const login=async()=>{S.em=v('em');const r=await post('login',{email:S.em,password:v('pw')});done(r.token)};
const reg=async()=>{S.em=v('em');done((await post('register',{email:S.em,password:v('pw'),username:v('un'),name:v('nm')})).token)};
const fg=async()=>{S.em=v('em');await post('forgot',{email:S.em});md('reset')};
const rs=async()=>done((await post('reset',{email:S.em,code:v('cd'),password:v('pw')})).token);
const done=t=>{S.tok=localStorage.k=t;boot()};
const out=()=>{localStorage.removeItem('k');S.tok=0;S.cur=null;boot()};

/* ---------- оболочка ---------- */
async function boot(){if(!S.tok)return auth();try{S.me=await api('me')}catch{return}S.tab='chats';S.cur=null;shell()}
function shell(){const T=[['chats','chat','Чаты'],['search','search','Поиск'],['me','user','Профиль']];if(S.me.is_admin)T.push(['admin','shield','Админ']);
R.innerHTML=`<div class="app ${S.cur?'open':''} ${S.tab=='me'||S.tab=='admin'?'page':''}"><nav>${T.map(t=>`<button class="${S.tab==t[0]?'on':''}" onclick="go('${t[0]}')" title="${t[2]}">${ic(t[1])}</button>`).join('')}</nav><section class=list id=L></section><section class=chat id=C></section></div>`;list();chatv()}
const go=t=>{S.tab=t;S.cur=null;shell()};
function list(){const L=$('#L');({chats:cl,search:sl,me:pl,admin:al})[S.tab](L)}
async function cl(L){if(!L.dataset.k){L.innerHTML='<h1>Чаты</h1><div id=cs></div>';L.dataset.k=1}const cs=await api('chats');if(S.tab!='chats'||!$('#cs'))return;
$('#cs').innerHTML=cs.length?cs.map((c,i)=>`<div class=row onclick='opn(${c.id},${JSON.stringify(c.peer).replace(/'/g,"&#39;")})'>${av(c.peer)}<div class=tx><b>${nm(c.peer)}</b><small>${c.mine?'Вы: ':''}${E(c.last)}</small></div><small>${dt(c.ts)}</small></div>`).join(''):'<div class=empty>Чатов пока нет.<br>Найдите людей во вкладке «Поиск».</div>'}
function sl(L){L.innerHTML='<h1>Поиск</h1><input class=f id=sq placeholder="Имя или @юзернейм" autocomplete=off><div id=sr></div>';let t;$('#sq').oninput=e=>{clearTimeout(t);t=setTimeout(async()=>{const x=e.target.value.trim();if(!x)return $('#sr').innerHTML='';const r=await api('search?q='+encodeURIComponent(x));$('#sr').innerHTML=r.length?r.map(u=>`<div class=row onclick="prof(${u.id})">${av(u)}<div class=tx><b>${nm(u)}</b><small>@${E(u.username)}</small></div></div>`).join(''):'<div class=empty>Никого не нашли</div>'},300)}}
async function opn(id,peer){S.cur={id,peer};S.msgs=[];shell();await pull()}
async function chatv(){const C=$('#C');if(!S.cur)return C.innerHTML='<div class=empty>Выберите чат слева</div>';const p=S.cur.peer;
C.innerHTML=`<div class=ch-h><button class=back onclick="S.cur=null;shell()">${ic('back')}</button><div style="display:flex;gap:12px;align-items:center;flex:1" onclick="prof(${p.id})">${av(p)}<div><b style="display:flex;gap:5px;align-items:center">${nm(p)}</b><small class=sm id=st>${stat(p)}</small></div></div></div><div id=M></div><div class=comp><span class=ib onclick="photo()">${ic('img')}</span><textarea id=tx rows=1 placeholder="Сообщение"></textarea><span class="ib p" onclick="snd()">${ic('send',20)}</span></div>`;
const t=$('#tx');t.onkeydown=e=>{if(e.key=='Enter'&&!e.shiftKey&&innerWidth>800){e.preventDefault();snd()}};t.oninput=()=>{t.style.height='auto';t.style.height=Math.min(120,t.scrollHeight)+'px'};draw(true)}
function draw(force){const M=$('#M');if(!M)return;const near=M.scrollHeight-M.scrollTop-M.clientHeight<120||force;const last=S.msgs[S.msgs.length-1];
M.innerHTML=S.msgs.length?S.msgs.map(m=>{const me=m.sender==S.me.id,o=m.media.startsWith('opts:')?m.media.slice(5).split('|'):[];return`<div class="m ${me?'me':''}">${m.media.startsWith('img:')?`<img src="${E(m.media.slice(4))}" onclick="window.open(this.src)">`:''}${E(m.text)}${o.length&&m==last?`<div class=opts>${o.map(x=>`<button onclick="quick('${x}')">${x}</button>`).join('')}</div>`:''}<time>${hm(m.ts)}</time></div>`}).join(''):'<div class=empty>Напишите первое сообщение</div>';if(near)M.scrollTop=M.scrollHeight}
async function pull(){if(!S.cur)return;const id=S.cur.id,a=S.msgs.length?S.msgs[S.msgs.length-1].id:0;const r=await api(`msgs/${id}?after=${a}`);if(!S.cur||S.cur.id!=id)return;if(r.length||!a){S.msgs=a?S.msgs.concat(r):r;draw()}}
async function snd(media){const t=$('#tx'),x=t.value.trim();if(!x&&!media)return;t.value='';t.style.height='auto';await api('msgs/'+S.cur.id,{text:x,media:media||''});pull()}
const quick=async x=>{await api('msgs/'+S.cur.id,{text:'Тема: '+x});pull()};
const photo=()=>pick(1280,d=>snd('img:'+d));

/* ---------- профили ---------- */
async function prof(id){if(id==S.me.id){S.tab='me';S.cur=null;return shell()}const u=await api('user/'+id);
const m=modal(`<div class=ban style="${u.banner?`background-image:url(${E(u.banner)})`:''}"></div><div class=av style="width:92px;height:92px;border:4px solid var(--bg1);margin:-46px 0 0 20px;font-size:32px">${u.avatar?`<img src="${E(u.avatar)}">`:E(u.name[0].toUpperCase())}</div><h1 style="display:flex;gap:6px;align-items:center;margin:10px 6px 0">${nm(u)}</h1><p class=sm style="margin:0 6px 8px">@${E(u.username)} · ${stat(u)}</p>${u.bio?`<p style="margin:8px 6px 14px">${E(u.bio)}</p>`:''}
<button class=pri onclick="wr(${u.id})">Написать</button>${u.official?'':`<div style="display:flex;gap:8px;margin-top:10px"><button class="sec" style="flex:1" onclick="blk(${u.id},this)">${u.blocked?'Разблокировать':'Заблокировать'}</button><button class="sec dng" style="flex:1" onclick="rep(${u.id})">Пожаловаться</button></div>`}`);window._m=m}
async function wr(id){const r=await api('chats',{peer:id});document.querySelector('.modal')?.remove();S.tab='chats';opn(r.id,r.peer)}
async function blk(id,b){const r=await api('block',{peer:id});b.textContent=r.blocked?'Разблокировать':'Заблокировать';toast(r.blocked?'Пользователь заблокирован':'Блокировка снята')}
function rep(id){document.querySelector('.modal')?.remove();modal(`<h1>Жалоба</h1><select class=f id=rr><option>Спам</option><option>Мошенничество</option><option>Оскорбления</option><option>Другое</option></select><textarea class=f id=rt rows=3 placeholder="Что случилось?"></textarea><button class=pri onclick="sendRep(${id})">Отправить</button>`)}
async function sendRep(id){await api('report',{target:id,reason:v('rr'),text:v('rt')});document.querySelector('.modal').remove();toast('Жалоба отправлена')}
function pl(L){const u=S.me;L.innerHTML=`<div class=pg><h1>Профиль</h1><div class=ban id=bn style="${u.banner?`background-image:url(${E(u.banner)})`:''}" onclick="pick(900,d=>{S.nb=d;bn.style.backgroundImage='url('+d+')'})"></div><div class="av big" id=ap style="font-size:32px" onclick="pick(300,d=>{S.na=d;ap.innerHTML='<img src='+d+'>'})">${u.avatar?`<img src="${E(u.avatar)}">`:E(u.name[0].toUpperCase())}</div><p class=sm style="margin:6px 6px 14px">Нажмите на баннер или аватар, чтобы заменить</p>
<input class=f id=pn value="${E(u.name)}" placeholder=Имя><input class=f id=pu value="${E(u.username)}" placeholder=Юзернейм oninput="chkP(this.value)"><div class=hint id=uh></div><textarea class=f id=pb rows=3 placeholder="О себе">${E(u.bio)}</textarea><button class=pri onclick=saveP()>Сохранить</button>
<div class=sec style="display:flex;justify-content:space-between;align-items:center;margin:16px 0 10px">Тёмная тема<button class=tg onclick="th()"></button></div><p class=sm style="margin:0 6px 12px">${E(u.email)}</p><button class="sec dng" style="width:100%" onclick=out()>Выйти</button></div>`}
function chkP(x){if(x==S.me.username)return $('#uh').textContent='';chkU(x)}
async function saveP(){const b={name:v('pn'),username:v('pu'),bio:v('pb')};if(S.na)b.avatar=S.na;if(S.nb)b.banner=S.nb;await api('me',b);S.na=S.nb=0;S.me=await api('me');toast('Сохранено')}
function th(){const d=document.documentElement;d.dataset.t=d.dataset.t=='dark'?'':'dark';localStorage.t=d.dataset.t}

/* ---------- админ-панель ---------- */
async function al(L){const s=await api('admin/stats');L.innerHTML=`<div class=pg><h1>Админ-панель</h1><div class=stats><div><b>${s.users}</b>пользователей</div><div><b>${s.online}</b>сейчас онлайн</div><div><b>${s.today}</b>новых за сутки</div><div><b>${s.msgs}</b>сообщений</div></div>
<div class=tabs>${[['users','Пользователи'],['reports','Жалобы ('+s.reports+')'],['support','Поддержка']].map(t=>`<button class="${S.at==t[0]?'on':''}" onclick="S.at='${t[0]}';list()">${t[1]}</button>`).join('')}</div><div id=ab></div></div>`;
({users:au,reports:ar,support:as_})[S.at]()}
async function au(){$('#ab').innerHTML='<input class=f id=aq placeholder="Поиск по почте, имени, юзернейму"><div id=ul></div>';let t;const load=async()=>{const r=await api('admin/users?q='+encodeURIComponent($('#aq').value));$('#ul').innerHTML=r.map(u=>`<div class=row onclick="achats(${u.id})">${av(u)}<div class=tx><b>${nm(u)}${u.chatban?' · бан чата':''}${u.banned?' · бан':''}</b><small>${E(u.email)} · @${E(u.username)}</small></div></div>${u.is_admin?'':`<div class=acts><button onclick="act(${u.id},'${u.chatban?'unchatban':'chatban'}')">${u.chatban?'Снять бан чата':'Бан чата'}</button><button onclick="act(${u.id},'${u.banned?'unban':'ban'}')">${u.banned?'Разбанить':'Бан входа'}</button><button class=dng onclick="act(${u.id},'blacklist')">В чёрный список</button><button class=dng onclick="act(${u.id},'delete')">Удалить</button></div>`}`).join('')||'<div class=empty>Пусто</div>'};$('#aq').oninput=()=>{clearTimeout(t);t=setTimeout(load,300)};load()}
async function act(uid,a){const T={delete:'Удалить аккаунт и все его чаты?',blacklist:'Удалить аккаунт и запретить регистрацию с этой почты?'};if(T[a]&&!confirm(T[a]))return;await api('admin/act',{uid,act:a});toast('Готово');au()}
async function achats(uid){const r=await api(`admin/user/${uid}/chats`);modal(`<h1>Чаты пользователя</h1>${r.map(c=>`<div class=row onclick="amsgs(${c.id})">${av(c.peer)}<div class=tx><b>${nm(c.peer)}</b><small>${E(c.last)}</small></div></div>`).join('')||'<div class=empty>Нет чатов</div>'}`)}
async function amsgs(id){const r=await api('admin/chat/'+id);modal(`<h1>Переписка</h1>${r.map(m=>`<p style="margin:8px 0"><b>${E(m.name)}</b> <small class=sm style="display:inline">${dt(m.ts)}</small><br>${m.media.startsWith('img:')?'[фото] ':''}${E(m.text)}</p>`).join('')}`)}
async function ar(){const r=await api('admin/reports');$('#ab').innerHTML=r.map(x=>`<div class=sec style="margin-bottom:8px"><b>${E(x.reason)}</b> · ${dt(x.ts)}<br><small class=sm style="white-space:normal">От @${E(x.au||'?')} на @${E(x.bu||'удалён')}</small><p style="margin-top:6px">${E(x.text)}</p></div>`).join('')||'<div class=empty>Жалоб нет</div>'}
async function as_(){const r=await api('admin/support');$('#ab').innerHTML=r.map(x=>`<div class=row onclick="sup(${x.uid},${x.chat})">${av(x.user)}<div class=tx><b>${nm(x.user)}${x.waiting?' · ждёт ответа':''}</b><small>${E(x.last)}</small></div><small>${dt(x.ts)}</small></div>`).join('')||'<div class=empty>Обращений нет</div>'}
async function sup(uid,chat){const r=await api('admin/chat/'+chat);modal(`<h1>Поддержка</h1>${r.map(m=>`<p style="margin:8px 0"><b>${E(m.name)}</b><br>${E(m.text)}</p>`).join('')}<textarea class=f id=sa rows=3 placeholder="Ответ от имени Klepa Support"></textarea><button class=pri onclick="supReply(${uid})">Отправить</button>`)}
async function supReply(uid){await api('admin/support',{uid,text:v('sa')});document.querySelector('.modal').remove();toast('Отправлено');list()}

setInterval(()=>{if(!S.tok||!S.me)return;if(S.cur)pull().catch(()=>{});else if(S.tab=='chats')cl($('#L')).catch(()=>{})},2500);
setInterval(async()=>{if(S.cur&&S.tok){try{const u=await api('user/'+S.cur.peer.id);S.cur.peer=u;const s=$('#st');if(s)s.textContent=stat(u)}catch{}}},15000);
fetch('/api/config').then(r=>r.json()).then(j=>{S.mail=j.mail;if(!S.tok&&S.mode=='login')auth()}).catch(()=>{});
boot();
</script></body></html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
