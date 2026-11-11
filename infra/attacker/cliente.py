import base64, hashlib, hmac, http.cookiejar as cj, os, struct, sys, time
import urllib.parse as up, urllib.request as ur


def totp(secret):
    chave = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    h = hmac.new(chave, struct.pack(">Q", int(time.time() // 30)), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def abridor(cookie):
    jar = cj.MozillaCookieJar(cookie)
    if os.path.exists(cookie):
        jar.load(ignore_discard=True, ignore_expires=True)
    return jar, ur.build_opener(ur.HTTPCookieProcessor(jar))


def pedir(op, metodo, url, campos=None):
    dados = up.urlencode(campos).encode() if campos is not None else None
    req = ur.Request(url, data=dados, method=metodo)
    try:
        r = op.open(req, timeout=15)
        return r.status, r.url
    except ur.HTTPError as e:
        return e.code, url


modo = sys.argv[1]
if modo == "login":
    base, usuario, senha, cookie = sys.argv[2:6]
    secret = sys.argv[6] if len(sys.argv) > 6 else None
    jar, op = abridor(cookie)
    st, url = pedir(op, "POST", base + "/login", {"usuario": usuario, "senha": senha})
    if secret:
        st, url = pedir(op, "POST", base + "/mfa", {"codigo": totp(secret)})
    jar.save(ignore_discard=True, ignore_expires=True)
    print(f"login status={st} url_final={url} cookies={[c.name for c in jar]}")
elif modo in ("get", "post"):
    base, caminho, cookie = sys.argv[2:5]
    campos = dict(p.split("=", 1) for p in sys.argv[5:]) if modo == "post" else None
    jar, op = abridor(cookie)
    st, url = pedir(op, modo.upper(), base + caminho, campos)
    print(f"{modo.upper()} {caminho} status={st} url_final={url}")
