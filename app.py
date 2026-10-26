import os, re, sqlite3, time, secrets, json, urllib.request
from functools import wraps
from flask import Flask, request, jsonify, g, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash

ADMIN = os.environ.get("ADMIN_EMAIL", "umarat239@gmail.com").lower()
DB = os.environ.get("DB_PATH", "klepa.db")
app = Flask(__name__, static_folder="static")
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
    return send_from_directory("static", "index.html")


@app.get("/api/username")
def uname():
    u = (request.args.get("u") or "").lower()
    if not valid_user(u):
        return jsonify(ok=False, why="4–20 символов: a–z, 0–9, _")
    return jsonify(ok=not q("select 1 from users where username=? and verified=1", (u,), True), why="Занято")


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
    run("insert into users(email,username,name,pw,is_admin,created) values(?,?,?,?,?,?)",
        (em, un, nm, generate_password_hash(pw), 1 if em == ADMIN else 0, time.time()))
    new_code(em, "reg")
    return jsonify(ok=True)


@app.post("/api/verify")
def verify():
    d = request.json or {}
    em = (d.get("email") or "").strip().lower()
    u = q("select * from users where email=?", (em,), True)
    if not u or not check_code(em, "reg", d.get("code")):
        return err("Неверный или просроченный код")
    run("update users set verified=1 where id=?", (u["id"],))
    support_hello(u["id"])
    return jsonify(token=session(u["id"]))


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
        new_code(em, "reg")
        return jsonify(need="verify")
    return jsonify(token=session(u["id"]))


@app.post("/api/forgot")
def forgot():
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
