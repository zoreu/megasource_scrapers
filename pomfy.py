"""
Pomfy Stream Scraper
================================

Protocolo MegaSource:
    TITLE, VERSION, DESCRIPTION
    get_streams(media_type, media_id, config=None) -> list[dict]

Fluxo:
  1) api.pomfy.stream/{filme|serie}/...  com Sec-Fetch-Dest: iframe
  2) /api/play-token -> byseUrl
  3) Resolve byse: challenge -> attest (ECDSA) -> PoW -> playback -> AES-GCM
"""

import base64
import hashlib
import http.cookiejar
import json
import random
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

TITLE = "Pomfy Scraper"
VERSION = "2.1.0"
DESCRIPTION = "Filmes e Series - Pomfy Stream (iframe + byse full)"

USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 11; X96 Max+) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36"
)

TMDB_API_KEY = (
    "\x33\x36\x34\x34\x64\x64\x34\x39\x35\x30\x62\x36\x37\x63\x64\x38"
    "\x30\x36\x37\x62\x38\x37\x37\x32\x64\x65\x35\x37\x36\x64\x36\x62"
)

STREAM_HEADERS = {"User-Agent": USER_AGENT,"Referer": "https://pomfy.online/"}

_cookiejar = http.cookiejar.CookieJar()
_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_cookiejar))


def _request(url, method="GET", data=None, headers=None, timeout=30):
    h = {"User-Agent": USER_AGENT, "Accept-Language": "pt-BR,pt;q=0.9"}
    if headers:
        h.update(headers)
    body = None
    if method == "POST" and data is not None:
        if isinstance(data, dict):
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            h.setdefault("Content-Type", "application/json")
        else:
            body = data
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            b = e.read().decode("utf-8", errors="replace")
        except Exception:
            b = ""
        return e.code, b
    except Exception:
        return 0, ""


def b64url_encode(data: bytes) -> str:
    return base64.b64encode(data).decode().replace("+", "-").replace("/", "_").rstrip("=")


def b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    while len(s) % 4:
        s += "="
    return base64.b64decode(s)


def random_bytes(n: int) -> bytes:
    return random.getrandbits(n * 8).to_bytes(n, "big")


# ============================================================
# AES-256-GCM (compatível com byse / aesgcm.py)
# ============================================================

SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


class AESCipher:
    def __init__(self, key):
        if len(key) != 32:
            raise ValueError("AES-256 key must be 32 bytes")
        self.rk = self._expand_key(key)

    def _expand_key(self, key):
        rk = [0] * 60
        for i in range(8):
            rk[i] = int.from_bytes(key[i * 4:(i + 1) * 4], "big")
        for i in range(8, 60):
            t = rk[i - 1]
            if i % 8 == 0:
                t = ((t << 8) | (t >> 24)) & 0xFFFFFFFF
                t = ((SBOX[t >> 24] << 24) | (SBOX[(t >> 16) & 0xFF] << 16) |
                     (SBOX[(t >> 8) & 0xFF] << 8) | SBOX[t & 0xFF])
                t ^= RCON[i // 8] << 24
            elif i % 8 == 4:
                t = ((SBOX[t >> 24] << 24) | (SBOX[(t >> 16) & 0xFF] << 16) |
                     (SBOX[(t >> 8) & 0xFF] << 8) | SBOX[t & 0xFF])
            rk[i] = (rk[i - 8] ^ t) & 0xFFFFFFFF
        return rk

    @staticmethod
    def _xtime(a):
        return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF

    def encrypt_block(self, block):
        state = [[0] * 4 for _ in range(4)]
        for c in range(4):
            for r in range(4):
                state[r][c] = block[c * 4 + r]

        def add_round_key(rnd):
            for c in range(4):
                k = self.rk[rnd * 4 + c]
                state[0][c] ^= (k >> 24) & 0xFF
                state[1][c] ^= (k >> 16) & 0xFF
                state[2][c] ^= (k >> 8) & 0xFF
                state[3][c] ^= k & 0xFF

        def sub_bytes():
            for r in range(4):
                for c in range(4):
                    state[r][c] = SBOX[state[r][c]]

        def shift_rows():
            state[1] = [state[1][1], state[1][2], state[1][3], state[1][0]]
            state[2] = [state[2][2], state[2][3], state[2][0], state[2][1]]
            state[3] = [state[3][3], state[3][0], state[3][1], state[3][2]]

        def mix_columns():
            for c in range(4):
                a, b, d, e = state[0][c], state[1][c], state[2][c], state[3][c]
                state[0][c] = self._xtime(a) ^ self._xtime(b) ^ b ^ d ^ e
                state[1][c] = a ^ self._xtime(b) ^ self._xtime(d) ^ d ^ e
                state[2][c] = a ^ b ^ self._xtime(d) ^ self._xtime(e) ^ e
                state[3][c] = self._xtime(a) ^ a ^ b ^ d ^ self._xtime(e)

        add_round_key(0)
        for r in range(1, 14):
            sub_bytes(); shift_rows(); mix_columns(); add_round_key(r)
        sub_bytes(); shift_rows(); add_round_key(14)
        out = bytearray(16)
        for c in range(4):
            for r in range(4):
                out[c * 4 + r] = state[r][c]
        return bytes(out)


_GCM_REDUCTION_TABLE = [
    0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
    0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
]


def _reverse_bits(i):
    i = ((i << 2) & 0xc) | ((i >> 2) & 0x3)
    i = ((i << 1) & 0xa) | ((i >> 1) & 0x5)
    return i


def _gcm_shift(x):
    high = x & 1
    x >>= 1
    if high:
        x ^= 0xe1 << (128 - 8)
    return x


def _build_product_table(h):
    table = [0] * 16
    table[_reverse_bits(1)] = h
    for i in range(2, 16, 2):
        table[_reverse_bits(i)] = _gcm_shift(table[_reverse_bits(i // 2)])
        table[_reverse_bits(i + 1)] = table[_reverse_bits(i)] ^ h
    return table


def _gcm_mul(y, product_table):
    ret = 0
    for _ in range(0, 128, 4):
        ret_high = ret & 0xf
        ret >>= 4
        ret ^= (_GCM_REDUCTION_TABLE[ret_high] << (128 - 16))
        ret ^= product_table[y & 0xf]
        y >>= 4
    return ret


def _bytes_to_number(b):
    return int.from_bytes(b, "big")


def _number_to_bytes(n, length=16):
    return n.to_bytes(length, "big")


def _gcm_update(y, data, product_table):
    for i in range(0, len(data) // 16):
        y ^= _bytes_to_number(data[16 * i:16 * i + 16])
        y = _gcm_mul(y, product_table)
    extra = len(data) % 16
    if extra:
        block = bytearray(16)
        block[:extra] = data[-extra:]
        y ^= _bytes_to_number(block)
        y = _gcm_mul(y, product_table)
    return y


def aes_gcm_decrypt(key, iv, ciphertext, tag, aad=b""):
    """AES-256-GCM (byse/aesgcm.py style). Does not fail on tag (empty AAD path)."""
    if len(key) != 32:
        raise ValueError("key 32 bytes")
    if len(iv) != 12:
        raise ValueError("iv 12 bytes")
    cipher = AESCipher(key)
    h = _bytes_to_number(cipher.encrypt_block(b"\x00" * 16))
    product_table = _build_product_table(h)
    counter = bytearray(16)
    counter[:12] = iv
    counter[15] = 1
    # tag_mask unused when skipping verify
    counter[15] = 2
    plaintext = bytearray()
    for i in range(0, len(ciphertext), 16):
        keystream = cipher.encrypt_block(bytes(counter))
        block = ciphertext[i:i + 16]
        for k in range(len(block)):
            plaintext.append(keystream[k] ^ block[k])
        for j in range(15, 11, -1):
            counter[j] = (counter[j] + 1) & 0xFF
            if counter[j] != 0:
                break
    return bytes(plaintext)


# ============================================================
# Fingerprint + ECDSA + PoW
# ============================================================

_ANDROID_PROFILES = [
    {
        "user_agent": "Mozilla/5.0 (Linux; Android 11; X96 Max+) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36",
        "model": "X96 Max+",
        "platform_version": "11.0.0",
        "hardware_concurrency": 4,
        "device_memory": 2,
        "pixel_ratio": 1,
        "screen_width": 1280,
        "screen_height": 720,
        "webgl_vendor": "Google Inc. (ARM)",
        "webgl_renderer": "ANGLE (ARM, Mali-G31 MP2, OpenGL ES 3.2)",
        "touch_points": 1,
        "pointer_type": "coarse",
    },
    {
        "user_agent": "Mozilla/5.0 (Linux; Android 11; SM-A037F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36",
        "model": "SM-A037F",
        "platform_version": "11.0.0",
        "hardware_concurrency": 4,
        "device_memory": 2,
        "pixel_ratio": 1.5,
        "screen_width": 720,
        "screen_height": 1600,
        "webgl_vendor": "Google Inc. (ARM)",
        "webgl_renderer": "ANGLE (ARM, Mali-G57 MP1, OpenGL ES 3.2)",
        "touch_points": 5,
        "pointer_type": "coarse,hover,touch",
    },
    {
        "user_agent": "Mozilla/5.0 (Linux; Android 10; TX6s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36",
        "model": "TX6s",
        "platform_version": "10.0.0",
        "hardware_concurrency": 4,
        "device_memory": 2,
        "pixel_ratio": 1,
        "screen_width": 1280,
        "screen_height": 720,
        "webgl_vendor": "Google Inc. (ARM)",
        "webgl_renderer": "ANGLE (ARM, Mali-G31 MP2, OpenGL ES 3.2)",
        "touch_points": 1,
        "pointer_type": "coarse",
    },
    {
        "user_agent": "Mozilla/5.0 (Linux; Android 10; Redmi 9A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36",
        "model": "Redmi 9A",
        "platform_version": "10.0.0",
        "hardware_concurrency": 4,
        "device_memory": 2,
        "pixel_ratio": 1.5,
        "screen_width": 720,
        "screen_height": 1600,
        "webgl_vendor": "Google Inc. (ARM)",
        "webgl_renderer": "ANGLE (ARM, Mali-G52 MC2, OpenGL ES 3.2)",
        "touch_points": 5,
        "pointer_type": "coarse,hover,touch",
    },
]

def generate_fingerprint():
    p = random.choice(_ANDROID_PROFILES)
    ua = p["user_agent"]
    r = random.random()
    return {
        "user_agent": ua,
        "architecture": "arm64-v8a",
        "bitness": "64",
        "platform": "Android",
        "platform_version": p["platform_version"],
        "model": p["model"],
        "ua_full_version": "137.0.7337.0",
        "brand_full_versions": [{"brand": "Chromium", "version": "137.0.7337.0"}, {"brand": "Not/A)Brand", "version": "24.0.0.0"}],
        "pixel_ratio": p["pixel_ratio"],
        "screen_width": p["screen_width"],
        "screen_height": p["screen_height"],
        "color_depth": 24,
        "languages": ["pt-BR"],
        "timezone": "America/Recife",
        "hardware_concurrency": p["hardware_concurrency"],
        "device_memory": p["device_memory"],
        "touch_points": p["touch_points"],
        "webgl_vendor": p["webgl_vendor"],
        "webgl_renderer": p["webgl_renderer"],
        "canvas_hash": b64url_encode(hashlib.sha256(str(r).encode()).digest()),
        "audio_hash": b64url_encode(hashlib.sha256(str(r + 1).encode()).digest()),
        "webgl_params_hash": b64url_encode(hashlib.sha256(str(r + 2).encode()).digest()),
        "fonts_hash": b64url_encode(hashlib.sha256(str(r + 3).encode()).digest()),
        "codecs_hash": b64url_encode(hashlib.sha256(str(r + 4).encode()).digest()),
        "media_devices": "ai1ao1vi4",
        "pointer_type": p["pointer_type"],
        "extra": {"vendor": "Google Inc.", "appVersion": ua[len("Mozilla/"):]}
    }

def make_attestation(challenge, client, viewer_id, device_id):
    challenge_id = challenge.get("challenge_id")
    nonce = challenge.get("nonce", "")
    priv, pub_x, pub_y = ECDSA_P256.generate_keypair()
    sig_bytes = ECDSA_P256.sign(priv, str(nonce).encode())
    sig = b64url_encode(sig_bytes)
    x = b64url_encode(pub_x.to_bytes(32, 'big'))
    y = b64url_encode(pub_y.to_bytes(32, 'big'))
    return {
        "viewer_id": viewer_id,
        "device_id": device_id,
        "challenge_id": challenge_id,
        "nonce": nonce,
        "signature": sig,
        "public_key": {"crv": "P-256", "ext": True, "key_ops": ["verify"], "kty": "EC", "x": x, "y": y},
        "client": client,
        "storage": {"cookie": viewer_id, "local_storage": viewer_id, "indexed_db": f"{viewer_id}:{device_id}", "cache_storage": f"{viewer_id}:{device_id}"},
        "attributes": {"entropy": "very_high"}
    }


class ECDSA_P256:
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

    @staticmethod
    def _mod_inv(a, m):
        m0, x0, x1 = m, 0, 1
        while a > 1:
            q = a // m
            a, m = m, a % m
            x0, x1 = x1 - q * x0, x0
        return x1 % m0

    @classmethod
    def _point_add(cls, P, Q):
        if P is None: return Q
        if Q is None: return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and y1 == y2:
            return cls._point_double(P)
        if x1 == x2:
            return None
        s = ((y2 - y1) * cls._mod_inv((x2 - x1) % cls.p, cls.p)) % cls.p
        x3 = (s * s - x1 - x2) % cls.p
        y3 = (s * (x1 - x3) - y1) % cls.p
        return (x3, y3)

    @classmethod
    def _point_double(cls, P):
        if P is None: return None
        x1, y1 = P
        if y1 == 0: return None
        s = ((3 * x1 * x1 + cls.a) * cls._mod_inv((2 * y1) % cls.p, cls.p)) % cls.p
        x3 = (s * s - 2 * x1) % cls.p
        y3 = (s * (x1 - x3) - y1) % cls.p
        return (x3, y3)

    @classmethod
    def _scalar_mult(cls, k, P):
        if k == 0 or P is None: return None
        result = None
        addend = P
        while k:
            if k & 1:
                result = cls._point_add(result, addend)
            addend = cls._point_double(addend)
            k >>= 1
        return result

    @classmethod
    def generate_keypair(cls):
        priv = random.randint(1, cls.n - 1)
        pub = cls._scalar_mult(priv, (cls.Gx, cls.Gy))
        return priv, pub[0], pub[1]

    @classmethod
    def sign(cls, priv, message):
        hash_int = int.from_bytes(hashlib.sha256(message).digest(), 'big')
        k = random.randint(1, cls.n - 1)
        kG = cls._scalar_mult(k, (cls.Gx, cls.Gy))
        if kG is None:
            raise RuntimeError("Erro ao gerar ponto kG")
        r = kG[0] % cls.n
        if r == 0:
            return cls.sign(priv, message)
        k_inv = cls._mod_inv(k, cls.n)
        s = (k_inv * (hash_int + priv * r)) % cls.n
        if s == 0:
            return cls.sign(priv, message)
        return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')

# ============================================================
# FINGERPRINT
# ============================================================

_ANDROID_PROFILES = [
    {
        "user_agent": "Mozilla/5.0 (Linux; Android 11; X96 Max+) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36",
        "model": "X96 Max+",
        "platform_version": "11.0.0",
        "hardware_concurrency": 4,
        "device_memory": 2,
        "pixel_ratio": 1,
        "screen_width": 1280,
        "screen_height": 720,
        "webgl_vendor": "Google Inc. (ARM)",
        "webgl_renderer": "ANGLE (ARM, Mali-G31 MP2, OpenGL ES 3.2)",
        "touch_points": 1,
        "pointer_type": "coarse",
    },
    {
        "user_agent": "Mozilla/5.0 (Linux; Android 11; SM-A037F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36",
        "model": "SM-A037F",
        "platform_version": "11.0.0",
        "hardware_concurrency": 4,
        "device_memory": 2,
        "pixel_ratio": 1.5,
        "screen_width": 720,
        "screen_height": 1600,
        "webgl_vendor": "Google Inc. (ARM)",
        "webgl_renderer": "ANGLE (ARM, Mali-G57 MP1, OpenGL ES 3.2)",
        "touch_points": 5,
        "pointer_type": "coarse,hover,touch",
    },
    {
        "user_agent": "Mozilla/5.0 (Linux; Android 10; TX6s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36",
        "model": "TX6s",
        "platform_version": "10.0.0",
        "hardware_concurrency": 4,
        "device_memory": 2,
        "pixel_ratio": 1,
        "screen_width": 1280,
        "screen_height": 720,
        "webgl_vendor": "Google Inc. (ARM)",
        "webgl_renderer": "ANGLE (ARM, Mali-G31 MP2, OpenGL ES 3.2)",
        "touch_points": 1,
        "pointer_type": "coarse",
    },
    {
        "user_agent": "Mozilla/5.0 (Linux; Android 10; Redmi 9A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36",
        "model": "Redmi 9A",
        "platform_version": "10.0.0",
        "hardware_concurrency": 4,
        "device_memory": 2,
        "pixel_ratio": 1.5,
        "screen_width": 720,
        "screen_height": 1600,
        "webgl_vendor": "Google Inc. (ARM)",
        "webgl_renderer": "ANGLE (ARM, Mali-G52 MC2, OpenGL ES 3.2)",
        "touch_points": 5,
        "pointer_type": "coarse,hover,touch",
    },
]

def generate_fingerprint():
    p = random.choice(_ANDROID_PROFILES)
    ua = p["user_agent"]
    r = random.random()
    return {
        "user_agent": ua,
        "architecture": "arm64-v8a",
        "bitness": "64",
        "platform": "Android",
        "platform_version": p["platform_version"],
        "model": p["model"],
        "ua_full_version": "137.0.7337.0",
        "brand_full_versions": [{"brand": "Chromium", "version": "137.0.7337.0"}, {"brand": "Not/A)Brand", "version": "24.0.0.0"}],
        "pixel_ratio": p["pixel_ratio"],
        "screen_width": p["screen_width"],
        "screen_height": p["screen_height"],
        "color_depth": 24,
        "languages": ["pt-BR"],
        "timezone": "America/Recife",
        "hardware_concurrency": p["hardware_concurrency"],
        "device_memory": p["device_memory"],
        "touch_points": p["touch_points"],
        "webgl_vendor": p["webgl_vendor"],
        "webgl_renderer": p["webgl_renderer"],
        "canvas_hash": b64url_encode(hashlib.sha256(str(r).encode()).digest()),
        "audio_hash": b64url_encode(hashlib.sha256(str(r + 1).encode()).digest()),
        "webgl_params_hash": b64url_encode(hashlib.sha256(str(r + 2).encode()).digest()),
        "fonts_hash": b64url_encode(hashlib.sha256(str(r + 3).encode()).digest()),
        "codecs_hash": b64url_encode(hashlib.sha256(str(r + 4).encode()).digest()),
        "media_devices": "ai1ao1vi4",
        "pointer_type": p["pointer_type"],
        "extra": {"vendor": "Google Inc.", "appVersion": ua[len("Mozilla/"):]}
    }

def make_attestation(challenge, client, viewer_id, device_id):
    challenge_id = challenge.get("challenge_id")
    nonce = challenge.get("nonce", "")
    priv, pub_x, pub_y = ECDSA_P256.generate_keypair()
    sig_bytes = ECDSA_P256.sign(priv, str(nonce).encode())
    sig = b64url_encode(sig_bytes)
    x = b64url_encode(pub_x.to_bytes(32, 'big'))
    y = b64url_encode(pub_y.to_bytes(32, 'big'))
    return {
        "viewer_id": viewer_id,
        "device_id": device_id,
        "challenge_id": challenge_id,
        "nonce": nonce,
        "signature": sig,
        "public_key": {"crv": "P-256", "ext": True, "key_ops": ["verify"], "kty": "EC", "x": x, "y": y},
        "client": client,
        "storage": {"cookie": viewer_id, "local_storage": viewer_id, "indexed_db": f"{viewer_id}:{device_id}", "cache_storage": f"{viewer_id}:{device_id}"},
        "attributes": {"entropy": "very_high"}
    }

# ============================================================
# PoW (HASH PERSONALIZADO)
# ============================================================

def _pow_hash(data: bytes):
    M = 0xFFFFFFFF
    LR, HR = 2654435761, 2246822519
    e0, e1, e2, e3 = 1779033703, 3144134277, 1013904242, 2773480762
    for b in data:
        e0 = (e0 + b) & M
        e0 = ((e0 << 7) | (e0 >> 25)) & M
        e0 = (e0 + e1) & M
        t = e3 ^ e0
        e3 = ((t << 16) | (t >> 16)) & M
        e2 = (e2 + e3) & M
        t = e1 ^ e2
        e1 = ((t << 12) | (t >> 20)) & M
        e0 = (e0 + e1) & M
        t = e3 ^ e0
        e3 = ((t << 8) | (t >> 24)) & M
        e2 = (e2 + e3) & M
        t = e1 ^ e2
        e1 = ((t << 7) | (t >> 25)) & M
    for _ in range(8):
        e0 = (e0 + e1) & M
        t = e3 ^ e0
        e3 = ((t << 16) | (t >> 16)) & M
        e2 = (e2 + e3) & M
        t = e1 ^ e2
        e1 = ((t << 12) | (t >> 20)) & M
        e0 = (e0 + e1) & M
        t = e3 ^ e0
        e3 = ((t << 8) | (t >> 24)) & M
        e2 = (e2 + e3) & M
        t = e1 ^ e2
        e1 = ((t << 7) | (t >> 25)) & M
    r = [0] * 512
    for i in range(512):
        e0 = (e0 + e1) & M
        t = e3 ^ e0
        e3 = ((t << 16) | (t >> 16)) & M
        e2 = (e2 + e3) & M
        t = e1 ^ e2
        e1 = ((t << 12) | (t >> 20)) & M
        e0 = (e0 + e1) & M
        t = e3 ^ e0
        e3 = ((t << 8) | (t >> 24)) & M
        e2 = (e2 + e3) & M
        t = e1 ^ e2
        e1 = ((t << 7) | (t >> 25)) & M
        r[i] = (e0 ^ e2) & M
    for _ in range(2):
        for s in range(512):
            a = r[s] & 511
            c = (r[s] + r[a]) & M
            c = ((c << 13) | (c >> 19)) & M
            c = (c ^ ((r[(s + 1) & 511] * LR) & M)) & M
            r[s] = c
            e0 = (e0 ^ c) & M
            e0 = (e0 + e1) & M
            t = e3 ^ e0
            e3 = ((t << 16) | (t >> 16)) & M
            e2 = (e2 + e3) & M
            t = e1 ^ e2
            e1 = ((t << 12) | (t >> 20)) & M
            e0 = (e0 + e1) & M
            t = e3 ^ e0
            e3 = ((t << 8) | (t >> 24)) & M
            e2 = (e2 + e3) & M
            t = e1 ^ e2
            e1 = ((t << 7) | (t >> 25)) & M
    n = [0] * 8
    for i in range(8):
        e0 = (e0 + e1) & M
        t = e3 ^ e0
        e3 = ((t << 16) | (t >> 16)) & M
        e2 = (e2 + e3) & M
        t = e1 ^ e2
        e1 = ((t << 12) | (t >> 20)) & M
        e0 = (e0 + e1) & M
        t = e3 ^ e0
        e3 = ((t << 8) | (t >> 24)) & M
        e2 = (e2 + e3) & M
        t = e1 ^ e2
        e1 = ((t << 7) | (t >> 25)) & M
        sv = e0
        base = i * 64
        for c in range(64):
            d = r[base + c]
            sv = (sv + d) & M
            sv = ((sv << 5) | (sv >> 27)) & M
            sv = (sv ^ ((d * HR) & M)) & M
        n[i] = (sv ^ e2) & M
    return n

def _lzbits(t):
    bits = 0
    for x in t:
        if x == 0:
            bits += 32
            continue
        return bits + (32 - x.bit_length())
    return bits

def solve_pow(nonce: str, difficulty: int, timeout_ms=90000):
    if difficulty <= 0:
        return "0"
    prefix = nonce + ":"
    start = time.time()
    s = random.randint(0, 1000000)
    while True:
        for _ in range(32768):
            if _lzbits(_pow_hash((prefix + str(s)).encode())) >= difficulty:
                return str(s)
            s += 1
        if (time.time() - start) * 1000 > timeout_ms:
            return None


# ============================================================
# Decode playback
# ============================================================

def decode_playback(playback_obj: dict):
    key_parts = playback_obj.get("key_parts", [])
    version_raw = playback_obj.get("version", 0)
    version = int(version_raw) if str(version_raw).isdigit() else 0

    if version and len(key_parts) >= version:
        idx1 = version - 1
        idx2 = len(key_parts) - version
        if idx1 < len(key_parts) and idx2 < len(key_parts):
            selected = [key_parts[idx1], key_parts[idx2]]
        else:
            selected = key_parts[:2]
    else:
        selected = key_parts[:2]

    key_bytes = b"".join(b64url_decode(p) for p in selected)
    if len(key_bytes) > 32:
        key_bytes = key_bytes[:32]

    iv = b64url_decode(playback_obj.get("iv", ""))
    if len(iv) > 12:
        iv = iv[:12]
    elif len(iv) < 12:
        iv = iv + b"\x00" * (12 - len(iv))

    payload = b64url_decode(playback_obj.get("payload", ""))
    if len(payload) < 16:
        return None
    ciphertext, tag = payload[:-16], payload[-16:]
    try:
        plaintext = aes_gcm_decrypt(key_bytes, iv, ciphertext, tag, b"")
        return json.loads(plaintext.decode("utf-8"))
    except Exception:
        return None


# ============================================================
# Resolve byse
# ============================================================

def resolve_byse(embed_url: str, parent_origin: str = "api.pomfy.stream", parent_page: str = None) -> Optional[str]:
    parsed = urllib.parse.urlparse(embed_url)
    api_base = f"{parsed.scheme}://{parsed.netloc}"
    video_id = parsed.path.strip("/").split("/")[-1]
    if not parent_page:
        parent_page = embed_url

    client = generate_fingerprint()
    base_headers = {
        "User-Agent": client["user_agent"],
        "Accept": "application/json, text/plain, */*",
        "Origin": api_base,
        "Referer": embed_url,
        "X-Embed-Origin": parent_origin,
        "X-Embed-Referer": embed_url,
        "X-Embed-Parent": parent_page,
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    }

    st, body = _request(f"{api_base}/api/videos/access/challenge", "POST", {}, base_headers)
    if st != 200:
        return None
    try:
        chal = json.loads(body)
    except Exception:
        return None

    viewer_id = chal.get("viewer_hint") or b64url_encode(random_bytes(16))
    device_id = b64url_encode(random_bytes(16))
    attest_payload = make_attestation(chal, client, viewer_id, device_id)
    st, body = _request(f"{api_base}/api/videos/access/attest", "POST", attest_payload, base_headers)
    if st != 200:
        return None
    try:
        att = json.loads(body)
    except Exception:
        return None

    viewer_id = att.get("viewer_id") or viewer_id
    device_id = att.get("device_id") or device_id
    fingerprint = {
        "token": att.get("token"),
        "viewer_id": viewer_id,
        "device_id": device_id,
        "confidence": att.get("confidence") or 0.93,
    }

    cookie_headers = dict(base_headers)
    cookie_headers["Cookie"] = f"byse_viewer_id={viewer_id}; byse_device_id={device_id}"

    st, body = _request(
        f"{api_base}/api/videos/{video_id}/embed/captcha",
        "POST",
        {"fingerprint": fingerprint},
        cookie_headers,
    )
    if st != 200:
        return None
    try:
        cap = json.loads(body)
    except Exception:
        return None

    solution = solve_pow(cap.get("pow_nonce"), cap.get("pow_difficulty", 0))
    if solution is None:
        return None

    st, body = _request(
        f"{api_base}/api/videos/{video_id}/embed/captcha/verify",
        "POST",
        {
            "pow_token": cap.get("pow_token"),
            "solution": solution,
            "fingerprint": fingerprint,
        },
        cookie_headers,
    )
    if st != 200:
        return None
    try:
        ver = json.loads(body)
    except Exception:
        return None
    captcha_token = ver.get("token")

    pb_headers = dict(cookie_headers)
    if captcha_token:
        pb_headers["X-Captcha-Token"] = captcha_token
    st, body = _request(
        f"{api_base}/api/videos/{video_id}/embed/playback",
        "POST",
        {"fingerprint": fingerprint},
        pb_headers,
    )
    if st != 200:
        return None
    try:
        pb = json.loads(body)
    except Exception:
        return None

    sources = pb.get("sources")
    if sources and len(sources) > 0:
        return sources[0].get("url")

    playback_obj = pb.get("playback")
    if not playback_obj:
        return None
    decrypted = decode_playback(playback_obj)
    if not decrypted:
        return None
    src = decrypted.get("sources") or (decrypted.get("data") or {}).get("sources")
    if src and len(src) > 0:
        return src[0].get("url")
    return decrypted.get("url")


# ============================================================
# Pomfy API (iframe) -> byseUrl
# ============================================================

def pomfy_get_byse_url(tmdb_id, media_type="movie", season=None, episode=None) -> Optional[str]:
    if media_type == "movie":
        path = f"filme/{tmdb_id}"
        parent = f"https://pomfy.online/assistir/{tmdb_id}"
        page_url = f"https://api.pomfy.stream/filme/{tmdb_id}"
    else:
        season = int(season) if season else 1
        episode = int(episode) if episode else 1
        path = f"serie/{tmdb_id}/{season}/{episode}"
        parent = f"https://pomfy.online/assistir/{tmdb_id}"
        page_url = f"https://api.pomfy.stream/serie/{tmdb_id}/{season}/{episode}"

    # CRÍTICO: Sec-Fetch-Dest iframe (senão Cloudflare 403)
    iframe_headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Referer": parent,
        "Sec-Fetch-Dest": "iframe",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "cross-site",
        "Upgrade-Insecure-Requests": "1",
    }
    st, body = _request(page_url, headers=iframe_headers)
    if st != 200:
        return None

    m = re.search(r'const statusToken="([^"]+)"', body)
    if not m:
        m = re.search(r'statusToken["\']?\s*[:=]\s*["\']([^"\']+)', body)
    if not m:
        return None
    token = m.group(1)

    st, body = _request(
        f"https://api.pomfy.stream/api/play-token?t={token}",
        headers={
            "accept": "*/*",
            "referer": page_url,
            "Origin": "https://api.pomfy.stream",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        },
    )
    if st != 200:
        return None
    try:
        data = json.loads(body)
    except Exception:
        return None
    return data.get("byseUrl") or data.get("url")


# ============================================================
# TMDB
# ============================================================

def imdb_to_tmdb(imdb_id: str, media_type: str = "movie") -> Optional[int]:
    url = (
        f"https://api.themoviedb.org/3/find/{imdb_id}"
        f"?api_key={TMDB_API_KEY}&external_source=imdb_id"
    )
    st, body = _request(url, headers={"Accept": "application/json"})
    if st != 200:
        return None
    try:
        data = json.loads(body)
    except Exception:
        return None
    key = "movie_results" if media_type == "movie" else "tv_results"
    results = data.get(key) or []
    if results:
        return results[0].get("id")
    return None


# ============================================================
# get_streams
# ============================================================

def get_streams(media_type: str, media_id: str, config: dict = None) -> list:
    imdb_id = media_id
    season = None
    episode = None
    if ":" in media_id:
        parts = media_id.split(":", 2)
        imdb_id = parts[0]
        if len(parts) > 1:
            season = parts[1]
        if len(parts) > 2:
            episode = parts[2]

    try:
        if str(imdb_id).lower().startswith("tt"):
            tmdb_id = imdb_to_tmdb(imdb_id, media_type)
            if not tmdb_id:
                return []
        else:
            tmdb_id = imdb_id

        byse_url = pomfy_get_byse_url(tmdb_id, media_type, season, episode)
        if not byse_url:
            return []

        if media_type == "movie":
            parent_page = f"https://api.pomfy.stream/filme/{tmdb_id}"
        else:
            s = int(season) if season else 1
            e = int(episode) if episode else 1
            parent_page = f"https://api.pomfy.stream/serie/{tmdb_id}/{s}/{e}"

        stream_url = resolve_byse(
            byse_url,
            parent_origin="api.pomfy.stream",
            parent_page=parent_page,
        )
        if not stream_url:
            return []

        stream_url = stream_url.replace("\\u0026", "&")
        return [
            {
                "name": TITLE,
                "title": "1080P",
                "url": stream_url,
                "behaviorHints": {
                    "notWebReady": True,
                    "proxyHeaders": {"request": STREAM_HEADERS},
                },
            }
        ]
    except Exception:
        return []

