from contextlib import asynccontextmanager
from datetime import datetime, timedelta
import hashlib
import hmac
import time
import redis.asyncio as aioredis
import stripe
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from random import randint
from typing import Annotated
from fastapi_csrf_protect import CsrfProtect
import os
import smtplib
import math
import secrets

from argon2 import PasswordHasher
from authx import AuthX, AuthXConfig
from database import get_session, engine
from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, Request, Depends, HTTPException, UploadFile
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from models import Base, Users, Flower, Order, OrderItem, Review, Card, Payment
import shutil 
import uvicorn
import json
import requests
import httpx
import traceback


# =========== SETTINGS ==============
load_dotenv()

# NOTE: this token was hardcoded in the source before — rotate it via @BotFather
# (it has effectively been leaked) and load it from .env going forward.
TOKEN = os.getenv("TG_BOT_TOKEN", "")

async def get_order(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Привет! Я бот цветов 🌸")

# Build the bot application object, but DO NOT start polling here.
# Application.builder()...build() just constructs the object — that's cheap and safe
# at module level. Actually starting it (run_polling / start_polling) has to happen
# inside an async context, which is why it's moved into the lifespan below.
tg_bot = Application.builder().token(TOKEN).build()
tg_bot.add_handler(CommandHandler("get_order", get_order))

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=BASE_DIR / "templates")

ph = PasswordHasher()

sender = os.getenv("MY_GMAIL")
email_password = os.getenv("MY_PASSWORD")
jwt_secret = os.getenv("TOP_SECRET_KEY")

CODE_LIFETIME_MINUTES = 10
MIN_PASSWORD_LENGTH = 6

YEREVAN_LAT = 40.20911821674716
YEREVAN_LNG = 44.467379830578224
DELIVERY_BASE_FEE = 1000
DELIVERY_RATE_PER_KM = 100

Session = Annotated[AsyncSession, Depends(get_session)]

config = AuthXConfig(
    JWT_SECRET_KEY=jwt_secret,

    JWT_ACCESS_COOKIE_NAME="My_access_Cookie",

    JWT_DECODE_ALGORITHMS=["HS256"],

    JWT_TOKEN_LOCATION=["cookies"],
    
    JWT_ACCESS_TOKEN_EXPIRES=timedelta(days=7),
    
    JWT_COOKIE_SECURE=False,

    JWT_COOKIE_CSRF_PROTECT=False,

    JWT_COOKIE_SAMESITE="lax",
)

auth_manager = AuthX(config=config)

# Redis-backed rate limiter (per-IP)
REDIS_CLIENT: aioredis.Redis | None = None
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 6  # max requests per window

# in-memory fallback store for CSRF when Redis is not available (dev only)
CSRF_STORE: dict[str, tuple[str, float]] = {}


async def is_rate_limited(ip: str) -> bool:
    global REDIS_CLIENT
    if REDIS_CLIENT is None:
        return False
    key = f"rl:{ip}"
    cnt = await REDIS_CLIENT.incr(key)
    if cnt == 1:
        await REDIS_CLIENT.expire(key, RATE_LIMIT_WINDOW)
    return cnt > RATE_LIMIT_MAX


def make_checkout_token(user_uid: str, flower_id: int, lifetime_seconds: int = 300) -> str:
    expires = int(time.time()) + lifetime_seconds
    payload = f"{user_uid}:{flower_id}:{expires}"
    sig = hmac.new(jwt_secret.encode() if jwt_secret else b"secret", payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def _extract_csrf_from_jwt(token: str) -> str | None:
    """Decode JWT payload without verification to extract common csrf claim names."""
    try:
        parts = token.split('.')
        if len(parts) < 2:
            return None
        import base64, json

        payload_b64 = parts[1]
        # add padding
        rem = len(payload_b64) % 4
        if rem:
            payload_b64 += '=' * (4 - rem)
        raw = base64.urlsafe_b64decode(payload_b64.encode())
        payload = json.loads(raw)
        for key in ("csrf", "csrf_token", "csrf_access_token", "csrfToken"):
            if key in payload:
                return str(payload[key])
        return None
    except Exception:
        return None


def _set_csrf_cookie_on_response(response, token: str):
    csrf = _extract_csrf_from_jwt(token)
    if csrf:
        # set cookie readable by JS so frontend can send header
        response.set_cookie("csrf_token", csrf, httponly=False, samesite="lax")


def _extract_jti_and_exp_from_jwt(token: str) -> tuple[str | None, int | None]:
    try:
        parts = token.split('.')
        if len(parts) < 2:
            return None, None
        import base64, json

        payload_b64 = parts[1]
        rem = len(payload_b64) % 4
        if rem:
            payload_b64 += '=' * (4 - rem)
        raw = base64.urlsafe_b64decode(payload_b64.encode())
        payload = json.loads(raw)
        return payload.get('jti'), int(payload.get('exp')) if payload.get('exp') else None
    except Exception:
        return None, None


async def _store_csrf_for_jti(jti: str, csrf: str, ttl_seconds: int):
    if not jti:
        return
    global REDIS_CLIENT, CSRF_STORE
    key = f"csrf:{jti}"
    try:
        if REDIS_CLIENT:
            await REDIS_CLIENT.setex(key, int(ttl_seconds), csrf)
            return
    except Exception:
        pass

    # fallback: memory store
    CSRF_STORE[jti] = (csrf, time.time() + int(ttl_seconds))


async def _get_stored_csrf_for_jti(jti: str) -> str | None:
    if not jti:
        return None
    global REDIS_CLIENT, CSRF_STORE
    key = f"csrf:{jti}"
    try:
        if REDIS_CLIENT:
            val = await REDIS_CLIENT.get(key)
            return val
    except Exception:
        pass

    tup = CSRF_STORE.get(jti)
    if not tup:
        return None
    val, exp = tup
    if time.time() > exp:
        del CSRF_STORE[jti]
        return None
    return val


async def attach_csrf_cookie_and_store(response, token: str):
    """Ensure a readable csrf cookie exists and store server-side keyed by token jti.

    - If JWT contains a non-empty csrf claim, use it and do not store.
    - Otherwise generate a secure csrf token, set cookie, and save under jti with TTL from token exp.
    """
    csrf_from_jwt = _extract_csrf_from_jwt(token)
    if csrf_from_jwt:
        response.set_cookie("csrf_token", csrf_from_jwt, httponly=False, samesite="lax")
        return

    # generate and store
    jti, exp = _extract_jti_and_exp_from_jwt(token)
    csrf_val = secrets.token_urlsafe(32)
    response.set_cookie("csrf_token", csrf_val, httponly=False, samesite="lax")
    ttl = 3600
    if exp:
        ttl = max(60, int(exp - time.time()))
    await _store_csrf_for_jti(jti, csrf_val, ttl)


def verify_checkout_token(token: str) -> tuple[bool, str | None]:
    try:
        parts = token.split(":")
        if len(parts) < 4:
            return False, None
        user_uid = parts[0]
        flower_id = int(parts[1])
        expires = int(parts[2])
        sig = parts[3]
        payload = f"{user_uid}:{flower_id}:{expires}"
        expected = hmac.new(jwt_secret.encode() if jwt_secret else b"secret", payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return False, None
        if int(time.time()) > expires:
            return False, None
        return True, user_uid
    except Exception:
        return False, None


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Start the Telegram bot's polling loop in the background, sharing the
    # same event loop uvicorn is already running. This replaces the old
    # blocking `tg_bot.run_polling()` call that prevented the app from
    # ever starting.
    await tg_bot.initialize()
    await tg_bot.start()
    await tg_bot.updater.start_polling()

    # initialize Redis client (if available) and Stripe API
    global REDIS_CLIENT
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    try:
        REDIS_CLIENT = aioredis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
    except Exception:
        REDIS_CLIENT = None

    stripe_api_key = os.getenv("STRIPE_SECRET_KEY")
    if stripe_api_key:
        stripe.api_key = stripe_api_key

    yield

    # Clean shutdown when the FastAPI app stops.
    await tg_bot.updater.stop()
    await tg_bot.stop()
    await tg_bot.shutdown()

    # close redis client
    try:
        if REDIS_CLIENT:
            await REDIS_CLIENT.close()
            await REDIS_CLIENT.connection_pool.disconnect()
    except Exception:
        pass


app = FastAPI(title="Karinka Flowers Shop", lifespan=lifespan)
auth_manager.handle_errors(app)

app.mount("/static", StaticFiles(directory="karinka_flowers/static"), name="static")
# =========== HELPERS ==================


@app.middleware("http")
async def bot_block_middleware(request: Request, call_next):
    """Block obvious bot traffic using simple User-Agent heuristics.

    Exempt static files and webhook/callback endpoints so services can reach them.
    This is a lightweight protection and can be tuned later.
    """
    path = request.url.path
    # quick allow-list for known endpoints
    EXEMPT_BOT_PATHS = ("/static", "/webhook", "/payment/callback", "/webhook/stripe")
    if any(path.startswith(p) for p in EXEMPT_BOT_PATHS):
        return await call_next(request)

    ua = request.headers.get("user-agent", "")
    if not ua:
        return JSONResponse({"detail": "Bot traffic blocked"}, status_code=403)

    ua_l = ua.lower()
    bot_signatures = (
        "bot", "spider", "crawl", "crawler", "curl", "wget", "python-requests",
        "httpx", "java/", "libwww-perl", "python-urllib", "axios", "postman",
        "okhttp", "scrapy",
    )
    for s in bot_signatures:
        if s in ua_l:
            return JSONResponse({"detail": "Bot traffic blocked"}, status_code=403)

    return await call_next(request)


@app.middleware("http")
async def upload_safety_middleware(request: Request, call_next):
    """Block requests with suspicious content-types commonly used to upload executable code.

    This is a lightweight, header-based check to drop requests that explicitly claim
    PHP/JS executable content. Real protection is enforced server-side in upload handlers.
    """
    path = request.url.path
    EXEMPT = ("/static", "/webhook", "/payment/callback", "/webhook/stripe")
    if any(path.startswith(p) for p in EXEMPT):
        return await call_next(request)

    ctype = request.headers.get("content-type", "").lower()
    # block content-types that indicate PHP or raw script uploads
    suspicious = (
        "application/x-httpd-php",
        "application/php",
        "text/php",
        "application/x-php",
    )
    for s in suspicious:
        if s in ctype:
            return JSONResponse({"detail": "Upload content type not allowed"}, status_code=415)

    return await call_next(request)

# Paths to skip AuthX CSRF enforcement (webhooks / external callbacks)
EXEMPT_PATHS_CSRF = [
    "/webhook/",
    "/payment/callback",
    "/webhook/stripe",
]


@app.middleware("http")
async def authx_csrf_middleware(request: Request, call_next):
    """Enforce AuthX CSRF for authenticated requests on state-changing methods.

    - If the request has no AuthX token (anonymous user), the middleware lets it pass
      (keeps existing guest flows working).
    - If the request includes an AuthX token, `verify_token(..., verify_csrf=True)`
      is called and a 403 is returned on failure.
    """
    # CSRF enforcement disabled (removed per request)
    return await call_next(request)

def render(req: Request, template_name: str, **context):
    return templates.TemplateResponse(
        name=template_name,
        request=req,
        context=context,
    )

TG_CHAT_ID = os.getenv("TG_CHAT_ID", "")  # например свой или админский


async def send_order_to_tg(order: dict, photo_path: str | Path | None = None):
 
    if order.get("lines"):
        lines_text = "\n".join(
            f"  • {ln['title']} × {ln['quantity']} = {ln['line_total']} AMD"
            for ln in order["lines"]
        )
        items_block = f"💐 Товары:\n{lines_text}"
    else:
        items_block = f"💐 Товар: {order['flower_title']}\n🔢 Количество: {order['quantity']}"
 
    caption = f"""
🌸 <b>Новый заказ #{order.get("order_id", "")}</b>
 
👤 {order["customer_name"]}
📞 {order["phone"]}
📍 {order["address"]}
 
{items_block}
🚚 Доставка: {order["delivery_fee"]} AMD
💰 Сумма (с доставкой): {order["price"]} AMD
 
💳 Оплата: {order["payment_method"]}
💬 Комментарий:
{order["comment"]}
"""
 
    async with httpx.AsyncClient() as client:
 
        if photo_path and Path(photo_path).exists():
 
            with open(photo_path, "rb") as photo:
 
                await client.post(
                    f"https://api.telegram.org/bot{TOKEN}/sendPhoto",
                    data={
                        "chat_id": TG_CHAT_ID,
                        "caption": caption,
                        "parse_mode": "HTML",
                    },
                    files={
                        "photo": photo
                    }
                )
 
        else:
 
            await client.post(
                f"https://api.telegram.org/bot{TOKEN}/sendMessage",
                data={
                    "chat_id": TG_CHAT_ID,
                    "text": caption,
                    "parse_mode": "HTML",
                }
            )

async def notify_order_confirmed(session: AsyncSession, order: "Order"):
    """Отправляет уведомление в Telegram. Вызывается ТОЛЬКО в момент
    подтверждения заказа (нал — кнопка "Подтвердить", карта — успешная оплата),
    а не в момент создания заказа.
 
    Поддерживает и старые одиночные заказы (order.flower_id), и новые
    мультитоварные (order.items)."""
 
    # мультитоварный заказ — есть order.items
    result = await session.execute(
        select(OrderItem).where(OrderItem.order_id == order.id)
    )
    items = result.scalars().all()
 
    if items:
        lines = []
        first_photo_path = None
        for item in items:
            flower_result = await session.execute(select(Flower).where(Flower.id == item.flower_id))
            flower = flower_result.scalar_one_or_none()
            title = flower.title if flower else "—"
            lines.append({
                "title": title,
                "quantity": item.quantity,
                "line_total": item.line_total,
            })
            if first_photo_path is None and flower and flower.image_path:
                candidate = BASE_DIR / flower.image_path.lstrip("/")
                if candidate.exists():
                    first_photo_path = candidate
 
        await send_order_to_tg({
            "order_id": order.id,
            "customer_name": order.customer_name,
            "phone": order.phone,
            "address": order.address,
            "lines": lines,
            "delivery_fee": order.delivery_fee,
            "price": order.price,
            "payment_method": order.payment_method,
            "comment": order.comment,
        }, first_photo_path)
        return
 
    # legacy — одиночный товар прямо на Order
    result = await session.execute(select(Flower).where(Flower.id == order.flower_id))
    flower = result.scalar_one_or_none()
    photo_path = BASE_DIR / flower.image_path.lstrip("/") if flower and flower.image_path else None
 
    await send_order_to_tg({
        "order_id": order.id,
        "customer_name": order.customer_name,
        "phone": order.phone,
        "address": order.address,
        "flower_title": flower.title if flower else "—",
        "quantity": order.quantity,
        "delivery_fee": order.price - ((flower.price * order.quantity) if flower and flower.price else 0),
        "price": order.price,
        "payment_method": order.payment_method,
        "comment": order.comment,
    }, photo_path)
 


async def send_review_to_tg(review: "Review"):
    """Уведомление в Telegram о новом отзыве — отдельно от заказов,
    чтобы админ сразу видел свежие отзывы, в том числе плохие."""

    stars = "★" * review.rating + "☆" * (5 - review.rating)

    caption = f"""
📝 <b>Новый отзыв</b>

👤 {review.author_name}
{stars}

💬 {review.text}
"""

    async with httpx.AsyncClient() as client:

        photo_full_path = None
        if review.photo_path:
            photo_full_path = BASE_DIR / review.photo_path.lstrip("/")

        if photo_full_path and photo_full_path.exists():
            with open(photo_full_path, "rb") as photo:
                await client.post(
                    f"https://api.telegram.org/bot{TOKEN}/sendPhoto",
                    data={
                        "chat_id": TG_CHAT_ID,
                        "caption": caption,
                        "parse_mode": "HTML",
                    },
                    files={"photo": photo},
                )
        else:
            await client.post(
                f"https://api.telegram.org/bot{TOKEN}/sendMessage",
                data={
                    "chat_id": TG_CHAT_ID,
                    "text": caption,
                    "parse_mode": "HTML",
                },
            )

def generate_code() -> str:
    return str(randint(100000, 999999))

def haversine_km(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lng2 - lng1)
    a = math.sin(d_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def calculate_delivery_fee(lat: float | None, lng: float | None) -> int:
    """Считаем доставку сами на сервере. Значению delivery_fee из формы
    не доверяем — его легко подделать через devtools перед отправкой."""
    if lat is None or lng is None:
        return DELIVERY_BASE_FEE
    try:
        distance_km = haversine_km(YEREVAN_LAT, YEREVAN_LNG, lat, lng)
    except (TypeError, ValueError):
        return DELIVERY_BASE_FEE
    return round(distance_km * DELIVERY_RATE_PER_KM) + DELIVERY_BASE_FEE

async def get_current_user_payload(request: Request):
    try:
        token = await auth_manager.get_token_from_request(request)
        if not token:
            return None

        payload = auth_manager.verify_token(token, verify_csrf=False)
        return payload
    except Exception as e:
        print(f"AUTH ERROR: {e}")
        return None


def extract_email_from_payload(payload) -> str | None:
    if not payload:
        return None

    if isinstance(payload, dict):
        return payload.get("uid") or payload.get("sub")

    return getattr(payload, "sub", None) or getattr(payload, "uid", None)


async def get_current_user_db(request: Request, session: AsyncSession):
    try:
        payload = await get_current_user_payload(request)
        email = extract_email_from_payload(payload)
        if not email:
            return None

        result = await session.execute(select(Users).where(Users.email == email))
        user = result.scalar_one_or_none()

        if not user:
            return None

        if getattr(user, "is_banned", False):
            return None

        return user
    except Exception:
        return None


def require_admin(user: Users | None):
    print(f"DEBUG require_admin: user={user!r} email={getattr(user,'email',None)} is_admin={getattr(user,'is_admin',None)}")
    if not user or not getattr(user, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")


def redirect_for_user(user: Users | None):
    return RedirectResponse("/admin" if user and getattr(user, "is_admin", False) else "/start", status_code=303)


# debug_request_info endpoint removed (was temporary for CSRF debugging)


@app.get("/debug/csrf-status")
async def debug_csrf_status(req: Request, session: Session):
    """Temporary admin-only diagnostic: shows token, jti, expected and stored CSRF info."""
    user = await get_current_user_db(req, session)
    require_admin(user)

    token = await auth_manager.get_token_from_request(req)
    expected = _extract_csrf_from_jwt(token) if token else None
    jti, exp = _extract_jti_and_exp_from_jwt(token) if token else (None, None)
    stored = None
    try:
        if jti:
            stored = await _get_stored_csrf_for_jti(jti)
    except Exception:
        stored = None

    def _mask(v: str | None) -> str | None:
        if v is None:
            return None
        s = str(v)
        if len(s) <= 12:
            return s
        return f"{s[:6]}...{s[-4:]}"

    return JSONResponse({
        "token_present": bool(token),
        "token_masked": _mask(token),
        "jti": jti,
        "exp": exp,
        "expected_csrf_masked": _mask(expected),
        "cookie_csrf_masked": _mask(req.cookies.get("csrf_token")),
        "header_csrf_masked": _mask(req.headers.get("x-csrf-token")),
        "stored_csrf_present": bool(stored),
        "stored_csrf_masked": _mask(stored),
    })


def send_verification_email(to_email: str, code: str) -> bool:
    if not sender or not email_password:
        print("MY_GMAIL или MY_PASSWORD не заданы")
        return False

    subject = "Подтверждение регистрации — Karinka Flowers"
    text_body = f"Ваш код подтверждения: {code}\n\nКод действителен {CODE_LIFETIME_MINUTES} минут."

    html_body = f"""
    <html>
    <body style="font-family:Arial,sans-serif;background:#f5f5f5;padding:30px;">
        <div style="
            max-width:500px;
            margin:auto;
            background:white;
            border-radius:16px;
            padding:30px;
            text-align:center;
            box-shadow:0 2px 10px rgba(0,0,0,0.1);
        ">
            <h2 style="color:#e91e63;">🌸 Karinka Flowers</h2>
            <p>Спасибо за регистрацию!</p>
            <p>Ваш код подтверждения:</p>
            <div style="
                font-size:40px;
                font-weight:bold;
                letter-spacing:10px;
                color:#e91e63;
                margin:20px 0;
            ">{code}</div>
            <p>Код действителен {CODE_LIFETIME_MINUTES} минут.</p>
            <p style="color:gray;font-size:12px;">
                Если вы не регистрировались — проигнорируйте это письмо.
            </p>
        </div>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to_email

    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(sender, email_password)
            smtp.sendmail(sender, to_email, msg.as_string())
        print(f"Email успешно отправлен на {to_email}")
        return True
    except Exception as e:
        print(f"Ошибка отправки email: {e}")
        return False


# =========== ROUTES ==================

@app.get("/")
async def logo(req: Request):
    return render(req, "logo.html")


@app.get("/enter")
async def enter(req: Request, session: Session):
    user = await get_current_user_db(req, session)
    if user:
        return redirect_for_user(user)
    return RedirectResponse("/home", status_code=303)


@app.get("/home")
async def home(req: Request):
    return render(req, "home.html")


@app.get("/register")
async def register_page(req: Request, session: Session):
    user = await get_current_user_db(req, session)
    if user:
        return redirect_for_user(user)
    return render(req, "register.html")


@app.post("/register")
async def register(req: Request, session: Session):
    user = await get_current_user_db(req, session)
    if user:
        return redirect_for_user(user)

    form = await req.form()
    username = form.get("name")
    email = form.get("email")
    password = form.get("password")
    confirm = form.get("confirm_password")

    if not all([username, email, password, confirm]):
        return render(req, "register.html", error="Заполните все поля!")

    if password != confirm:
        return render(req, "register.html", error="Пароли не совпадают!")

    result = await session.execute(select(Users).where(Users.email == email))
    existing_user = result.scalar_one_or_none()

    if existing_user and existing_user.is_verified:
        return render(req, "register.html", error="Пользователь с таким email уже существует!")

    result = await session.execute(select(Users).where(Users.username == username))
    existing_user = result.scalar_one_or_none()
    
    if existing_user and existing_user.is_verified:
        return render(req, "register.html", error="Пользователь с таким username уже существует!")
    
    hashed_password = ph.hash(password)
    code = generate_code()
    expires_at = datetime.utcnow() + timedelta(minutes=CODE_LIFETIME_MINUTES)

    if existing_user and not existing_user.is_verified:
        existing_user.username = username
        existing_user.password = hashed_password
        existing_user.verification_code = code
        existing_user.code_expires_at = expires_at
        existing_user.is_banned = False
    else:
        new_user = Users(
            username=username,
            email=email,
            password=hashed_password,
            is_verified=False,
            is_admin=False,
            is_banned=False,
            verification_code=code,
            code_expires_at=expires_at,
        )
        session.add(new_user)

    await session.commit()

    if not send_verification_email(email, code):
        return render(req, "register.html", error="Не удалось отправить письмо на почту.")

    return RedirectResponse(url=f"/verify-email?email={email}", status_code=303)


@app.get("/verify-email")
async def verify_email_page(req: Request, email: str, session: Session):
    user = await get_current_user_db(req, session)
    if user:
        return redirect_for_user(user)

    return render(req, "verify_email.html", email=email)


@app.post("/verify-email")
async def verify_email(req: Request, session: Session):
    user_cookie = await get_current_user_db(req, session)
    if user_cookie:
        return redirect_for_user(user_cookie)

    form = await req.form()
    email = form.get("email")
    code = form.get("code")

    if not email or not code:
        return render(req, "verify_email.html", email=email, error="Введите код подтверждения!")

    result = await session.execute(select(Users).where(Users.email == email))
    user = result.scalar_one_or_none()

    if not user:
        return RedirectResponse("/register", status_code=303)

    if user.is_banned:
        return render(req, "login.html", error="Ваш аккаунт заблокирован администратором.")

    if user.is_verified:
        token = auth_manager.create_access_token(uid=email)
        response = RedirectResponse("/start", status_code=303)
        auth_manager.set_access_cookies(token, response)
        return response

    if user.code_expires_at and user.code_expires_at < datetime.utcnow():
        return render(req, "verify_email.html", email=email, error="Код устарел. Запросите новый.")

    if user.verification_code != code:
        return render(req, "verify_email.html", email=email, error="Неверный код.")

    user.is_verified = True
    user.verification_code = None
    user.code_expires_at = None
    await session.commit()

    token = auth_manager.create_access_token(uid=email)
    response = RedirectResponse(url="/start", status_code=303)
    auth_manager.set_access_cookies(token, response)
    return response


@app.post("/verify-email/resend")
async def resend_code(req: Request, session: Session):
    user_cookie = await get_current_user_db(req, session)
    if user_cookie:
        return redirect_for_user(user_cookie)

    form = await req.form()
    email = form.get("email")

    if not email:
        return RedirectResponse("/register", status_code=303)

    result = await session.execute(select(Users).where(Users.email == email))
    user = result.scalar_one_or_none()

    if not user or user.is_verified:
        return RedirectResponse(url="/home", status_code=303)

    code = generate_code()
    user.verification_code = code
    user.code_expires_at = datetime.utcnow() + timedelta(minutes=CODE_LIFETIME_MINUTES)
    await session.commit()

    if not send_verification_email(email, code):
        return render(req, "verify_email.html", email=email, error="Не удалось отправить новый код.")

    return render(req, "verify_email.html", email=email, info="Новый код отправлен на почту.")


@app.get("/login")
async def login_page(req: Request, session: Session):
    user = await get_current_user_db(req, session)
    if user:
        return redirect_for_user(user)

    return render(req, "login.html")


@app.post("/login")
async def login(req: Request, session: Session):
    user_cookie = await get_current_user_db(req, session)
    if user_cookie:
        return redirect_for_user(user_cookie)

    form = await req.form()
    username = form.get("username")
    password = form.get("password")

    if not username or not password:
        return render(req, "login.html", error="Заполните все поля!")

    result = await session.execute(select(Users).where(Users.username == username))
    user = result.scalar_one_or_none()

    if not user:
        return render(req, "login.html", error="Неверный username или пароль!")

    if getattr(user, "is_banned", False):
        return render(req, "login.html", error="Ваш аккаунт заблокирован администратором.")

    try:
        ph.verify(user.password, password)
    except Exception:
        return render(req, "login.html", error="Неверный username или пароль!")

    if not user.is_verified:
        return render(req, "login.html", error="Сначала подтвердите email!")

    token = auth_manager.create_access_token(uid=user.email)
    response = RedirectResponse("/admin" if user.is_admin else "/start", status_code=303)
    auth_manager.set_access_cookies(token, response)
    return response


@app.get("/logout")
async def logout():
    response = RedirectResponse("/home", status_code=303)
    response.delete_cookie(config.JWT_ACCESS_COOKIE_NAME, path="/")
    return response

@app.get('/about')
async def about(req: Request, session: Session):
    user = await get_current_user_db(req, session)    
    return render(req, "about.html") 

@app.get("/start")
async def start(req: Request, session: Session):
    user = await get_current_user_db(req, session)
    if not user:
        return RedirectResponse("/login", status_code=303)

    result = await session.execute(
        select(Flower).order_by(Flower.id.desc())
    )
    flowers = result.scalars().all()

    categories = sorted({
        flower.category for flower in flowers if flower.category
    })

    display_label = user.username or (user.email.split("@")[0] if user.email else "Гость")
    display_initial = display_label[:1].upper() if display_label else "?"

    return render(
        req,
        "start.html",
        user=user,
        flowers=flowers,
        categories=categories,
        display_label=display_label,
        display_initial=display_initial,
    )


@app.get("/profile")
async def profile_page(req: Request, session: Session):
    user = await get_current_user_db(req, session)
    if not user:
        return RedirectResponse("/login", status_code=303)

    return render(req, "profile.html", user=user)


@app.post("/profile")
async def update_profile(req: Request, session: Session):
    user = await get_current_user_db(req, session)
    if not user:
        return RedirectResponse("/login", status_code=303)

    form = await req.form()
    new_username = (form.get("username") or "").strip()
    current_password = form.get("current_password") or ""
    new_password = form.get("new_password") or ""
    confirm_password = form.get("confirm_password") or ""

    username_changed = False

    # --- Смена имени пользователя ---
    if new_username and new_username != user.username:
        existing = await session.execute(
            select(Users).where(Users.username == new_username, Users.id != user.id)
        )
        if existing.scalar_one_or_none():
            return render(req, "profile.html", user=user, error="Это имя пользователя уже занято.")

        user.username = new_username
        username_changed = True

    # --- Смена пароля (только если пользователь заполнил блок пароля) ---
    password_changed = False
    if current_password or new_password or confirm_password:
        if not (current_password and new_password and confirm_password):
            return render(req, "profile.html", user=user, error="Чтобы сменить пароль, заполните все три поля.")

        try:
            ph.verify(user.password, current_password)
        except Exception:
            return render(req, "profile.html", user=user, error="Текущий пароль указан неверно.")

        if new_password != confirm_password:
            return render(req, "profile.html", user=user, error="Новые пароли не совпадают.")

        if len(new_password) < MIN_PASSWORD_LENGTH:
            return render(
                req, "profile.html", user=user,
                error=f"Новый пароль должен быть не короче {MIN_PASSWORD_LENGTH} символов.",
            )

        user.password = ph.hash(new_password)
        password_changed = True

    if not username_changed and not password_changed:
        return render(req, "profile.html", user=user, error="Нет изменений для сохранения.")

    await session.commit()

    if username_changed and password_changed:
        success = "Имя пользователя и пароль обновлены."
    elif username_changed:
        success = "Имя пользователя обновлено."
    else:
        success = "Пароль обновлён."

    return render(req, "profile.html", user=user, success=success)


@app.get("/admin")
async def admin_panel(req: Request, session: Session):
    user = await get_current_user_db(req, session)
    require_admin(user)

    total_users = await session.scalar(select(func.count()).select_from(Users))
    verified_users = await session.scalar(
        select(func.count()).select_from(Users).where(Users.is_verified == True)  # noqa: E712
    )
    banned_users = await session.scalar(
        select(func.count()).select_from(Users).where(Users.is_banned == True)  # noqa: E712
    )
    admins_count = await session.scalar(
        select(func.count()).select_from(Users).where(Users.is_admin == True)  # noqa: E712
    )

    total_users = total_users or 0
    verified_users = verified_users or 0
    banned_users = banned_users or 0
    admins_count = admins_count or 0

    # Производные числа для графиков в админке (не требуют новых полей в БД)
    unverified_users = max(total_users - verified_users, 0)
    active_users = max(total_users - banned_users, 0)
    regular_users = max(total_users - admins_count, 0)

    result = await session.execute(select(Users).order_by(Users.id.desc()))
    users = result.scalars().all()

    return render(
        req,
        "admin.html",
        user=user,
        total_users=total_users,
        verified_users=verified_users,
        banned_users=banned_users,
        admins_count=admins_count,
        unverified_users=unverified_users,
        active_users=active_users,
        regular_users=regular_users,
        users=users,
    )


@app.post("/admin/toggle-ban/{user_id}")
async def admin_toggle_ban(user_id: int, req: Request, session: Session):
    admin = await get_current_user_db(req, session)
    require_admin(admin)

    result = await session.execute(select(Users).where(Users.id == user_id))
    target = result.scalar_one_or_none()

    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    if target.id == admin.id:
        raise HTTPException(status_code=400, detail="Нельзя заблокировать самого себя")

    if target.is_admin:
        raise HTTPException(status_code=400, detail="Нельзя банить другого администратора")

    target.is_banned = not target.is_banned
    await session.commit()

    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/toggle-admin/{user_id}")
async def admin_toggle_admin(user_id: int, req: Request, session: Session):
    admin = await get_current_user_db(req, session)
    require_admin(admin)

    result = await session.execute(select(Users).where(Users.id == user_id))
    target = result.scalar_one_or_none()

    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    if target.id == admin.id:
        raise HTTPException(status_code=400, detail="Нельзя снять/дать админку самому себе")

    target.is_admin = not target.is_admin
    await session.commit()

    return RedirectResponse("/admin", status_code=303)

@app.post("/admin/flowers")
async def add_flower(
    req: Request,
    session: Session,
    title: str = Form(...),
    category: str = Form(...),
    description: str = Form(...),
    price: float = Form(...),
    stock: int = Form(0),
    image: UploadFile = File(...),
):
    user = await get_current_user_db(req, session)
    require_admin(user)

    if price < 0:
        raise HTTPException(status_code=400, detail="Цена не может быть отрицательной")

    if stock < 0:
        raise HTTPException(status_code=400, detail="Остаток не может быть отрицательным")

    upload_dir = Path("karinka_flowers/static/uploads")
    upload_dir.mkdir(parents=True, exist_ok=True)

    # Validate uploaded image extension and MIME type
    allowed_ext = {".jpg", ".jpeg", ".png", ".webp", ".gif"}
    allowed_mimetypes = {"image/jpeg", "image/png", "image/webp", "image/gif"}

    file_ext = Path(image.filename).suffix.lower()
    content_type = (image.content_type or "").lower()
    if file_ext not in allowed_ext or content_type not in allowed_mimetypes:
        raise HTTPException(status_code=415, detail="Invalid image upload type")

    safe_name = f"{int(datetime.utcnow().timestamp())}{file_ext}"
    file_path = upload_dir / safe_name

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(image.file, buffer)

    flower = Flower(
        title=title,
        category=category,
        description=description,
        price=price,
        image_path=f"/static/uploads/{safe_name}",
        stock=stock,
    )
    session.add(flower)
    await session.commit()

    return RedirectResponse("/start", status_code=303)

@app.get("/order/{flower_id}")
async def order_page(flower_id: int, req: Request, session: Session):
    user = await get_current_user_db(req, session)
    if not user:
        return RedirectResponse("/login", status_code=303)

    result = await session.execute(select(Flower).where(Flower.id == flower_id))
    flower = result.scalar_one_or_none()

    if not flower:
        raise HTTPException(status_code=404, detail="Товар не найден")

    cards_result = await session.execute(
        select(Card).where(Card.user_id == user.id).order_by(Card.id.desc())
    )
    cards = cards_result.scalars().all()

    display_label = user.username or (user.email.split("@")[0] if user.email else "Гость")
    display_initial = display_label[:1].upper() if display_label else "?"

    return render(
        req,
        "order.html",
        user=user,
        flower=flower,
        cards=cards,
        display_label=display_label,
        display_initial=display_initial,
    )


@app.post("/order/{flower_id}")
async def create_order(
    flower_id: int,
    req: Request,
    session: Session,
    customer_name: str = Form(...),
    phone: str = Form(...),
    address: str = Form(...),
    quantity: int = Form(1),
    payment_method: str = Form(...),
    comment: str = Form(""),
    lat: float | None = Form(None),
    lng: float | None = Form(None),
    card_id: int | None = Form(None),
):
    user = await get_current_user_db(req, session)
    if not user:
        return RedirectResponse("/login", status_code=303)

    result = await session.execute(select(Flower).where(Flower.id == flower_id))
    flower = result.scalar_one_or_none()

    if not flower:
        raise HTTPException(status_code=404, detail="Товар не найден")

    display_label = user.username or (user.email.split("@")[0] if user.email else "Гость")
    display_initial = display_label[:1].upper() if display_label else "?"

    cards_result = await session.execute(
        select(Card).where(Card.user_id == user.id).order_by(Card.id.desc())
    )
    cards = cards_result.scalars().all()

    def render_order_error(message: str):
        return render(
            req, "order.html", user=user, flower=flower, cards=cards,
            display_label=display_label, display_initial=display_initial,
            error=message,
        )

    # --- проверки остатка (на сервере, а не только в браузере) ---
    if not phone.startswith("+374"):
        return render_order_error("Номер телефона должен начинаться с +374.")

    digits = phone[4:]  # убираем +374

    if not digits.isdigit():
        return render_order_error("Номер телефона должен содержать только цифры после +374.")
    
    if len(digits) != 8:
        return render_order_error("Номер телефона должен содержать 8 цифр после +374.")
    
    if flower.stock <= 0:
        return render_order_error("Этот букет закончился на складе.")

    if quantity < 1:
        return render_order_error("Количество должно быть не меньше 1.")

    if quantity > flower.stock:
        return render_order_error(f"На складе осталось всего {flower.stock} шт. Уменьшите количество.")

    payment_method = payment_method.strip().lower()
    if payment_method not in ("cash", "card"):
        raise HTTPException(status_code=400, detail="Неверный способ оплаты")

    card = None
    if payment_method == "card":
        if not card_id:
            return render_order_error("Выберите карту для оплаты или добавьте новую.")

        card_result = await session.execute(
            select(Card).where(Card.id == card_id, Card.user_id == user.id)
        )
        card = card_result.scalar_one_or_none()
        if not card:
            return render_order_error("Выбранная карта не найдена. Выберите другую или добавьте новую.")

    delivery_fee = calculate_delivery_fee(lat, lng)
    order_price = (flower.price or 0) * quantity + delivery_fee

    order = Order(
        user_id=user.id,
        flower_id=flower.id,
        customer_name=customer_name,
        phone=phone,
        address=address,
        quantity=quantity,
        comment=comment,
        payment_method=payment_method,
        price=order_price,
        status="new",
    )
    photo_path = BASE_DIR / flower.image_path.lstrip("/")

    flower.stock -= quantity  # списываем остаток

    session.add(order)
    await session.commit()
    await session.refresh(order)

    payment_label = payment_method
    if card:
        payment_label = f"{payment_method} ({card.brand.upper()} •••• {card.last4})"

    return RedirectResponse(f"/confirm_order/{order.id}", status_code=303)
    
    
@app.delete("/delete/{flower_id}")
async def delete_flower(
    flower_id: int,
    req: Request,
    session: Session
):
    user = await get_current_user_db(req, session)
    require_admin(user)

    result = await session.execute(
        select(Flower).where(Flower.id == flower_id)
    )
    flower = result.scalar_one_or_none()

    if not flower:
        raise HTTPException(status_code=404, detail="Flower not found")

    try:
        await session.delete(flower)
        await session.commit()
    except IntegrityError:
        await session.rollback()
        raise HTTPException(
            status_code=409,
            detail="Нельзя удалить этот цветок — по нему уже есть заказы. Сначала удалите или обработайте связанные заказы.",
        )

    return {"success": True}


# =========== NEW: Checkout & Payment API ==============

@app.post("/checkout")
async def checkout_cart(
    req: Request,
    session: Session,
    customer_name: str = Form(...),
    phone: str = Form(...),
    address: str = Form(...),
    payment_method: str = Form(...),
    comment: str = Form(""),
    lat: float | None = Form(None),
    lng: float | None = Form(None),
    card_id: int | None = Form(None),
    # корзина приходит одной строкой JSON: '[{"id":"3","qty":2},{"id":"7","qty":1}]'
    cart_items: str = Form(...),
):
    """Оформляет ВСЮ корзину одним заказом: несколько товаров, одна доставка."""
    user = await get_current_user_db(req, session)
    if not user:
        return RedirectResponse("/login", status_code=303)

    display_label = user.username or (user.email.split("@")[0] if user.email else "Гость")
    display_initial = display_label[:1].upper() if display_label else "?"

    try:
        raw_items = json.loads(cart_items)
    except Exception:
        raise HTTPException(status_code=400, detail="Некорректные данные корзины")

    if not raw_items:
        raise HTTPException(status_code=400, detail="Корзина пуста")

    def render_checkout_error(message: str):
        # Показываем ошибку через query-параметр, чтобы каталог/корзина могли её отрисовать
        return RedirectResponse(f"/start?cart_error={message}", status_code=303)

    if not phone.startswith("+374"):
        return render_checkout_error("Номер телефона должен начинаться с +374.")

    digits = phone[4:]
    if not digits.isdigit() or len(digits) != 8:
        return render_checkout_error("Номер телефона должен содержать 8 цифр после +374.")

    payment_method = payment_method.strip().lower()
    if payment_method not in ("cash", "card"):
        raise HTTPException(status_code=400, detail="Неверный способ оплаты")

    card = None
    if payment_method == "card":
        if not card_id:
            return render_checkout_error("Выберите карту для оплаты или добавьте новую.")
        card_result = await session.execute(
            select(Card).where(Card.id == card_id, Card.user_id == user.id)
        )
        card = card_result.scalar_one_or_none()
        if not card:
            return render_checkout_error("Выбранная карта не найдена.")

    # --- собираем и валидируем позиции корзины по данным из БД, не доверяя ценам с клиента ---
    flowers_subtotal = 0.0
    validated_lines = []  # (flower, quantity)

    for raw in raw_items:
        try:
            flower_id = int(raw.get("id"))
            qty = int(raw.get("qty", 1))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Некорректная позиция в корзине")

        if qty < 1:
            continue

        result = await session.execute(select(Flower).where(Flower.id == flower_id))
        flower = result.scalar_one_or_none()
        if not flower:
            return render_checkout_error(f"Товар #{flower_id} больше не найден в каталоге.")

        if flower.stock <= 0:
            return render_checkout_error(f"«{flower.title}» закончился на складе.")

        if qty > flower.stock:
            return render_checkout_error(f"«{flower.title}» — доступно только {flower.stock} шт.")

        validated_lines.append((flower, qty))
        flowers_subtotal += (flower.price or 0) * qty

    if not validated_lines:
        return render_checkout_error("Корзина пуста или все товары недоступны.")

    delivery_fee = calculate_delivery_fee(lat, lng)
    order_price = flowers_subtotal + delivery_fee

    order = Order(
        user_id=user.id,
        flower_id=None,
        quantity=None,
        customer_name=customer_name,
        phone=phone,
        address=address,
        comment=comment,
        payment_method=payment_method,
        price=order_price,
        delivery_fee=delivery_fee,
        status="new",
    )
    session.add(order)
    await session.flush()  # получаем order.id до commit, чтобы привязать OrderItem

    for flower, qty in validated_lines:
        session.add(OrderItem(
            order_id=order.id,
            flower_id=flower.id,
            quantity=qty,
            unit_price=flower.price or 0,
        ))
        flower.stock -= qty  # списываем остаток по каждой позиции

    await session.commit()
    await session.refresh(order)

    return RedirectResponse(f"/confirm_order/{order.id}", status_code=303)

@app.post("/api/checkout/{flower_id}")
async def api_checkout(
    flower_id: int,
    req: Request,
    session: Session,
    customer_name: str = Form(...),
    phone: str = Form(...),
    address: str = Form(...),
    quantity: int = Form(1),
    payment_method: str = Form(...),
    comment: str = Form(""),
    lat: float | None = Form(None),
    lng: float | None = Form(None),
):
    """Создаёт заказ через API для асинхронного checkout'а"""
    user = await get_current_user_db(req, session)
    if not user:
        raise HTTPException(status_code=401, detail="Не авторизован")

    # rate limit per IP
    ip = req.client.host if req.client else "unknown"
    if await is_rate_limited(ip):
        raise HTTPException(status_code=429, detail="Слишком много запросов, повторите позже")

    # require checkout token to mitigate fake orders
    form = await req.form()
    token = form.get("checkout_token") or req.headers.get("X-Checkout-Token")
    if not token:
        raise HTTPException(status_code=400, detail="Отсутствует checkout token")
    valid, uid = verify_checkout_token(token)
    if not valid or uid != extract_email_from_payload(await get_current_user_payload(req)):
        raise HTTPException(status_code=400, detail="Неверный или просроченный токен заказа")

    result = await session.execute(select(Flower).where(Flower.id == flower_id))
    flower = result.scalar_one_or_none()
    if not flower:
        raise HTTPException(status_code=404, detail="Товар не найден")

    # basic validations (reuse same rules as HTML form)
    if not phone.startswith("+374"):
        raise HTTPException(status_code=400, detail="Номер телефона должен начинаться с +374.")

    digits = phone[4:]
    if not digits.isdigit() or len(digits) != 8:
        raise HTTPException(status_code=400, detail="Неверный телефонный номер.")

    if flower.stock <= 0:
        return JSONResponse({"status": "error", "message": "Товар закончился"}, status_code=400)

    if quantity < 1 or quantity > flower.stock:
        return JSONResponse({"status": "error", "message": "Неверное количество"}, status_code=400)

    payment_method = payment_method.strip().lower()
    if payment_method not in ("cash", "card"):
        raise HTTPException(status_code=400, detail="Неверный способ оплаты")

    delivery_fee = calculate_delivery_fee(lat, lng)
    order_price = (flower.price or 0) * quantity + delivery_fee

    order = Order(
        user_id=user.id,
        flower_id=flower.id,
        customer_name=customer_name,
        phone=phone,
        address=address,
        quantity=quantity,
        comment=comment,
        payment_method=payment_method,
        price=order_price,
        status="pending",
    )

    flower.stock -= quantity
    session.add(order)
    await session.commit()
    await session.refresh(order)
    
    # For UI flow, redirect to confirm page; for JS clients, they can use the redirect field
    return {"status": "ok", "order_id": order.id, "price": order_price, "redirect": f"/confirm_order/{order.id}"}


@app.post("/api/payment/session/{order_id}")
async def create_payment_session(order_id: int, session: Session):
    """Создаёт (симулирует) платёжную сессию и возвращает URL"""
    result = await session.execute(select(Order).where(Order.id == order_id))
    order = result.scalar_one_or_none()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    # mark as pending if still new
    if order.status in (None, "new"):
        order.status = "pending"
        await session.commit()

    payment_url = f"/payment/gateway/{order.id}"
    return {"payment_url": payment_url}


@app.post("/api/payment/stripe/session/{order_id}")
async def create_stripe_session(order_id: int, req: Request, session: Session):
    """Create a Stripe Checkout Session for the order and return redirect url.
    Note: currency is set to USD for demo — adjust to supported currency and conversion in production."""
    if not stripe.api_key:
        raise HTTPException(status_code=501, detail="Stripe not configured")

    result = await session.execute(select(Order).where(Order.id == order_id))
    order = result.scalar_one_or_none()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    # create a Checkout Session
    try:
        session_obj = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "product_data": {"name": f"Order #{order.id}"},
                    "unit_amount": int((order.price or 0) * 100),
                },
                "quantity": 1,
            }],
            mode="payment",
            success_url=os.getenv("STRIPE_SUCCESS_URL", f"{os.getenv('BASE_URL','http://localhost:8000')}/payment/success?order_id={order.id}"),
            cancel_url=os.getenv("STRIPE_CANCEL_URL", f"{os.getenv('BASE_URL','http://localhost:8000')}/payment/fail?order_id={order.id}"),
            metadata={"order_id": str(order.id)},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"payment_url": session_obj.url}


@app.post("/webhook/stripe")
async def stripe_webhook(req: Request, session: Session):
    payload = await req.body()
    sig_header = req.headers.get("stripe-signature")
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    if not webhook_secret:
        raise HTTPException(status_code=501, detail="Stripe webhook secret not configured")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Webhook error: {e}")

    # Handle the checkout.session.completed event
    if event["type"] == "checkout.session.completed":
        data = event["data"]["object"]
        order_id = data.get("metadata", {}).get("order_id")
        if order_id:
            result = await session.execute(select(Order).where(Order.id == int(order_id)))
            order = result.scalar_one_or_none()
            if order:
                order.status = "paid"
                await session.commit()
                await notify_order_confirmed(session, order)

    return JSONResponse({"received": True})


# =========== Ameriabank VPOS integration ==============

AMERI_VPOS_URL = os.getenv("AMERIABANK_VPOS_URL", "https://servicestest.ameriabank.am/VPOS")
AMERI_CLIENT = os.getenv("AMERIABANK_CLIENTID")
AMERI_USERNAME = os.getenv("AMERIABANK_USERNAME")
AMERI_PASSWORD = os.getenv("AMERIABANK_PASSWORD")


async def vpos_post(action: str, data: dict) -> dict | str:
    url = AMERI_VPOS_URL.rstrip("/") + "/" + action.lstrip("/")
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=data, timeout=15)
        try:
            return resp.json()
        except Exception:
            return resp.text


@app.post("/payment/init/{order_id}")
async def ameriabank_init(order_id: int, req: Request, session: Session):
    """Server-to-server InitPayment -> GetPaymentId -> redirect user to bank page"""
    if not (AMERI_CLIENT and AMERI_USERNAME and AMERI_PASSWORD):
        raise HTTPException(status_code=501, detail="Ameriabank credentials not configured")

    result = await session.execute(select(Order).where(Order.id == order_id))
    order = result.scalar_one_or_none()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    # create Payment record
    payment = Payment(
        order_id=order.id,
        provider="ameriabank",
        amount=order.price,
        currency="AMD",
        status="initiated",
    )
    session.add(payment)
    await session.commit()
    await session.refresh(payment)

    back_url = os.getenv("BASE_URL", "http://localhost:8000") + "/payment/callback"

    init_body = {
        "ClientID": AMERI_CLIENT,
        "Username": AMERI_USERNAME,
        "Password": AMERI_PASSWORD,
        "Amount": int(order.price),
        "OrderID": str(order.id),
        "BackURL": back_url,
        "Currency": payment.currency,
        "Description": f"Order #{order.id}"
    }

    init_resp = await vpos_post("InitPayment", init_body)
    # save raw response
    payment.bank_response = json.dumps(init_resp) if not isinstance(init_resp, str) else str(init_resp)
    await session.commit()

    # Get PaymentId
    get_body = {"ClientID": AMERI_CLIENT, "Username": AMERI_USERNAME, "Password": AMERI_PASSWORD, "OrderID": str(order.id)}
    get_resp = await vpos_post("GetPaymentId", get_body)

    payment_id = None
    if isinstance(get_resp, dict):
        payment_id = get_resp.get("PaymentId") or get_resp.get("PaymentID") or get_resp.get("paymentId")
        payment.payment_url = get_resp.get("PaymentURL") or get_resp.get("PaymentUrl")
    else:
        # try to parse simple string for PaymentId
        text = str(get_resp)
        # fallback: no structured response
        payment_id = None

    if payment_id:
        payment.payment_id = str(payment_id)
    await session.commit()

    # Construct redirect URL — prefer payment.payment_url if provided
    if payment.payment_url:
        redirect_to = payment.payment_url
    elif payment.payment_id:
        # common pattern: bank may expect a redirect with PaymentId
        redirect_to = AMERI_VPOS_URL.rstrip("/") + "/Payment?PaymentId=" + str(payment.payment_id)
    else:
        # fallback: redirect to internal gateway for manual test
        redirect_to = f"/payment/gateway/{order.id}"

    # store payment_url
    payment.payment_url = redirect_to
    await session.commit()

    return RedirectResponse(redirect_to)


@app.post("/payment/callback")
async def ameriabank_callback(req: Request, session: Session):
    """Handle bank BackURL call. Verify payment and confirm."""
    form = await req.form()
    # Common fields: PaymentID, OrderID, Amount, Status
    payment_id = form.get("PaymentID") or form.get("PaymentId") or form.get("paymentId")
    order_id = form.get("OrderID") or form.get("OrderId") or form.get("orderId")

    # try to find payment/order
    payment = None
    order = None
    if payment_id:
        result = await session.execute(select(Payment).where(Payment.payment_id == str(payment_id)))
        payment = result.scalar_one_or_none()
        if payment:
            result = await session.execute(select(Order).where(Order.id == payment.order_id))
            order = result.scalar_one_or_none()

    if not order and order_id:
        result = await session.execute(select(Order).where(Order.id == int(order_id)))
        order = result.scalar_one_or_none()
        if order:
            result = await session.execute(select(Payment).where(Payment.order_id == order.id))
            payment = result.scalar_one_or_none()

    # check payment status via GetPaymentDetails
    details = None
    if payment and payment.payment_id:
        det_body = {"PaymentID": payment.payment_id, "Username": AMERI_USERNAME, "Password": AMERI_PASSWORD}
        details = await vpos_post("GetPaymentDetails", det_body)
        payment.bank_response = json.dumps(details) if not isinstance(details, str) else str(details)

    # decide success based on details content or callback
    success = False
    if isinstance(details, dict):
        # look for common success indicators
        st = details.get("Status") or details.get("status") or details.get("Result")
        if st and str(st).lower() in ("ok", "success", "paid", "completed"):
            success = True

    # fallback: check callback field
    if not success:
        cb_status = form.get("Status") or form.get("status")
        if cb_status and str(cb_status).lower() in ("ok", "success", "paid", "completed"):
            success = True

    if success and order and payment:
        payment.status = "paid"
        order.status = "paid"
        await session.commit()
        # optionally call ConfirmPayment
        try:
            conf_body = {"PaymentID": payment.payment_id, "Username": AMERI_USERNAME, "Password": AMERI_PASSWORD, "Amount": int(payment.amount)}
            await vpos_post("ConfirmPayment", conf_body)
        except Exception:
            pass

        return RedirectResponse(f"/payment/success?order_id={order.id}")

    return RedirectResponse(f"/payment/fail?order_id={order.id if order else ''}")


@app.get("/api/checkout/token/{flower_id}")
async def get_checkout_token(flower_id: int, req: Request, session: Session):
    """Returns a short-lived signed token for client-side checkout requests."""
    user = await get_current_user_db(req, session)
    if not user:
        raise HTTPException(status_code=401, detail="Не авторизован")

    result = await session.execute(select(Flower).where(Flower.id == flower_id))
    flower = result.scalar_one_or_none()
    if not flower:
        raise HTTPException(status_code=404, detail="Товар не найден")

    token = make_checkout_token(user.email or user.username or str(user.id), flower_id)
    return {"checkout_token": token}


@app.get("/payment/gateway/{order_id}")
async def payment_gateway(order_id: int, req: Request, session: Session):
    """Simple simulated gateway page with success/fail links."""
    result = await session.execute(select(Order).where(Order.id == order_id))
    order = result.scalar_one_or_none()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    html = f"""
    <html>
      <head><meta charset="utf-8"><title>Оплата заказа #{order.id}</title></head>
      <body style="font-family:Arial,sans-serif;max-width:700px;margin:40px auto;text-align:center;">
        <h2>Оплата заказа #{order.id}</h2>
        <p>Сумма: <strong>{order.price} AMD</strong></p>
        <p>Нажмите кнопку для имитации успешной оплаты или ошибки.</p>
        <div style="display:flex;gap:12px;justify-content:center;margin-top:24px;">
          <a style="padding:12px 18px;background:#4caf50;color:white;border-radius:8px;text-decoration:none;" href="/payment/success?order_id={order.id}">Оплатить (успех)</a>
          <a style="padding:12px 18px;background:#f44336;color:white;border-radius:8px;text-decoration:none;" href="/payment/fail?order_id={order.id}">Отмена/Ошибка</a>
        </div>
      </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get("/confirm_order/{order_id}")
async def confirm_order_page(order_id: int, req: Request, session: Session):
    user = await get_current_user_db(req, session)
    result = await session.execute(select(Order).where(Order.id == order_id))
    order = result.scalar_one_or_none()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    items_result = await session.execute(
        select(OrderItem).where(OrderItem.order_id == order.id)
    )
    order_items = items_result.scalars().all()

    order_lines = []
     
    flower = None 
     
    if order_items:
        # мультитоварный заказ
        for item in order_items:
            fl_result = await session.execute(select(Flower).where(Flower.id == item.flower_id))
            fl = fl_result.scalar_one_or_none()
            order_lines.append({
                "title": fl.title if fl else "—",
                "image_path": fl.image_path if fl else None,
                "quantity": item.quantity,
                "unit_price": item.unit_price,
                "line_total": item.line_total,
            })
    else:
        # legacy — один товар прямо на Order
        result = await session.execute(select(Flower).where(Flower.id == order.flower_id))
        flower = result.scalar_one_or_none()

    return render(
        req, "confirm_order.html",
        user=user, order=order, flower=flower, order_lines=order_lines,
    )
    
@app.get("/checkout")
async def checkout_page(req: Request, session: Session):
    user = await get_current_user_db(req, session)
    if not user:
        return RedirectResponse("/login", status_code=303)

    cards_result = await session.execute(
        select(Card).where(Card.user_id == user.id).order_by(Card.id.desc())
    )
    cards = cards_result.scalars().all()

    display_label = user.username or (user.email.split("@")[0] if user.email else "Гость")
    display_initial = display_label[:1].upper() if display_label else "?"

    # Товары корзины лежат в localStorage браузера (не на сервере),
    # поэтому шаблон checkout.html подгружает и рендерит их через JS.
    cards_json = json.dumps([
        {
            "id": c.id,
            "brand": c.brand,
            "last4": c.last4,
            "exp_month": c.exp_month,
            "exp_year": c.exp_year,
        }
        for c in cards
    ])
    
    return render(
        req, "checkout.html",
        user=user, cards_json=cards_json,
        display_label=display_label, display_initial=display_initial,
    )


@app.post("/confirm_order/{order_id}/pay")
async def confirm_order_pay(order_id: int, req: Request, session: Session):
    """Финальное подтверждение заказа пользователем.
    Для наличной оплаты — это реальное подтверждение (курьер привезёт и примет деньги).
    Для карты — ручное подтверждение (реальная онлайн-оплата идёт через /payment/init
    или Stripe webhook — там уведомление шлётся отдельно)."""
    result = await session.execute(select(Order).where(Order.id == order_id))
    order = result.scalar_one_or_none()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    if order.status in ("paid", "confirmed"):
        return RedirectResponse(f"/payment/success?order_id={order.id}")

    if order.payment_method == "cash":
        order.status = "confirmed"
        payment = Payment(order_id=order.id, provider="cash", amount=order.price, currency="AMD", status="confirmed")
    else:
        order.status = "paid"
        payment = Payment(order_id=order.id, provider="manual_confirm", amount=order.price, currency="AMD", status="paid")

    session.add(payment)
    await session.commit()

    await notify_order_confirmed(session, order)

    return RedirectResponse(f"/payment/success?order_id={order.id}")


@app.get("/payment/success")
async def payment_success(req: Request, order_id: int | None = None, session: Session = None):
    """Отображает страницу успешной оплаты. Помечает заказ как paid при наличии order_id."""
    if order_id and session:
        result = await session.execute(select(Order).where(Order.id == order_id))
        order = result.scalar_one_or_none()
        if order:
            order.status = "paid"
            await session.commit()

    html = """
    <html><head><meta charset="utf-8"><title>Оплата успешна</title></head>
    <body style="font-family:Arial,sans-serif;text-align:center;margin:60px;">
      <h2>Оплата прошла</h2>
      <p>Спасибо — ваш платёж принят.</p>
      <a href="/start">Вернуться в магазин</a>
    </body></html>
    """
    return HTMLResponse(content=html)


@app.get("/payment/fail")
async def payment_fail(req: Request, order_id: int | None = None, session: Session = None):
    if order_id and session:
        result = await session.execute(select(Order).where(Order.id == order_id))
        order = result.scalar_one_or_none()
        if order:
            order.status = "failed"
            await session.commit()

    html = """
    <html><head><meta charset="utf-8"><title>Оплата не прошла</title></head>
    <body style="font-family:Arial,sans-serif;text-align:center;margin:60px;">
      <h2>Оплата не прошла</h2>
      <p>Платёж отменён или произошла ошибка.</p>
      <a href="/start">Вернуться в магазин</a>
    </body></html>
    """
    return HTMLResponse(content=html)


@app.get("/api/order/{order_id}")
async def get_order(order_id: int, session: Session):
    result = await session.execute(select(Order).where(Order.id == order_id))
    order = result.scalar_one_or_none()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    return {"id": order.id, "status": order.status, "price": order.price}


@app.post("/api/order/{order_id}/status")
async def update_order_status(order_id: int, req: Request, session: Session, status: str = Form(...)):
    allowed = {"pending", "paid", "failed", "delivered", "new"}
    if status not in allowed:
        raise HTTPException(status_code=400, detail="Invalid status")

    # try to detect admin first
    admin_user = None
    try:
        admin_user = await get_current_user_db(req, session) if req is not None else None
    except Exception:
        admin_user = None

    result = await session.execute(select(Order).where(Order.id == order_id))
    order = result.scalar_one_or_none()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    # allow status updates by admin; basic gateway flow may update to paid without admin
    if not admin_user and status not in ("paid", "failed"):
        raise HTTPException(status_code=403, detail="Only admin can set this status")

    order.status = status
    await session.commit()
    return {"success": True, "status": order.status}


@app.post("/api/delivery/calc")
async def delivery_calc(lat: float = Form(...), lng: float = Form(...)):
    fee = calculate_delivery_fee(lat, lng)
    return {"delivery_fee": fee}


@app.post("/api/checkout/validate")
async def validate_checkout(session: Session, flower_id: int = Form(...), quantity: int = Form(...)):
    result = await session.execute(select(Flower).where(Flower.id == flower_id))
    flower = result.scalar_one_or_none()
    if not flower:
        raise HTTPException(status_code=404, detail="Flower not found")

    ok = quantity >= 1 and quantity <= (flower.stock or 0)
    price = (flower.price or 0) * quantity
    return {"ok": ok, "available_stock": flower.stock, "price": price}


@app.get("/api/admin/orders")
async def get_orders(req: Request, session: Session):
    admin = await get_current_user_db(req, session)
    require_admin(admin)

    result = await session.execute(select(Order).order_by(Order.id.desc()))
    orders = result.scalars().all()
    out = []
    for o in orders:
        out.append({
            "id": o.id,
            "user_id": o.user_id,
            "flower_id": o.flower_id,
            "status": o.status,
            "price": o.price,
            "created_at": getattr(o, "created_at", None),
        })
    return {"orders": out}


# =========== КАРТЫ ==================

@app.post("/cards")
async def add_card(
    req: Request,
    session: Session,
    brand: str = Form(...),
    last4: str = Form(...),
    holder_name: str = Form(...),
    exp_month: int = Form(...),
    exp_year: int = Form(...),
):
    user = await get_current_user_db(req, session)
    if not user:
        raise HTTPException(status_code=401, detail="Не авторизован")

    last4 = "".join(ch for ch in last4 if ch.isdigit())
    if len(last4) != 4:
        raise HTTPException(status_code=400, detail="Нужно ровно 4 цифры")

    brand = brand.strip().lower()
    if brand not in ("visa", "mastercard", "mir", "card"):
        brand = "card"

    holder_name = holder_name.strip()
    if not holder_name:
        raise HTTPException(status_code=400, detail="Укажите имя на карте")

    if not (1 <= exp_month <= 12):
        raise HTTPException(status_code=400, detail="Неверный месяц")

    current_year = datetime.utcnow().year
    if exp_year < current_year or exp_year > current_year + 15:
        raise HTTPException(status_code=400, detail="Неверный год")

    card = Card(
        user_id=user.id,
        brand=brand,
        last4=last4,
        holder_name=holder_name,
        exp_month=exp_month,
        exp_year=exp_year,
    )
    session.add(card)
    await session.commit()
    await session.refresh(card)

    return {
        "id": card.id,
        "brand": card.brand,
        "last4": card.last4,
        "holder_name": card.holder_name,
        "exp_month": card.exp_month,
        "exp_year": card.exp_year,
    }


@app.delete("/cards/{card_id}")
async def delete_card(card_id: int, req: Request, session: Session):
    user = await get_current_user_db(req, session)
    if not user:
        raise HTTPException(status_code=401, detail="Не авторизован")

    result = await session.execute(
        select(Card).where(Card.id == card_id, Card.user_id == user.id)
    )
    card = result.scalar_one_or_none()
    if not card:
        raise HTTPException(status_code=404, detail="Карта не найдена")

    await session.delete(card)
    await session.commit()
    return {"success": True}


# =========== ОТЗЫВЫ ==================

@app.get('/review')
async def otziv(req: Request, session: Session):
    user = await get_current_user_db(req, session)
    if not user:
        return RedirectResponse("/login", status_code=303)

    result = await session.execute(select(Review).order_by(Review.created_at.desc()))
    reviews = result.scalars().all()

    return render(
        req,
        "review.html",
        user=user,
        reviews=reviews,
    )


@app.post('/review')
async def create_review(
    req: Request,
    session: Session,
    rating: int = Form(...),
    text: str = Form(...),
    photo: UploadFile = File(None),
):
    user = await get_current_user_db(req, session)
    if not user:
        return RedirectResponse("/login", status_code=303)

    text = (text or "").strip()
    if not text:
        result = await session.execute(select(Review).order_by(Review.created_at.desc()))
        reviews = result.scalars().all()
        return render(req, ".html", user=user, reviews=reviews, error="Напишите текст отзыва.")

    # ограничиваем оценку диапазоном 1..5, даже если форму подменили
    rating = max(1, min(5, rating))

    photo_path = None
    if photo and photo.filename:
        upload_dir = Path("karinka_flowers/static/uploads/reviews")
        upload_dir.mkdir(parents=True, exist_ok=True)

        allowed_ext = {".jpg", ".jpeg", ".png", ".webp", ".gif"}
        allowed_mimetypes = {"image/jpeg", "image/png", "image/webp", "image/gif"}

        file_ext = Path(photo.filename).suffix.lower()
        content_type = (photo.content_type or "").lower()
        if file_ext not in allowed_ext or content_type not in allowed_mimetypes:
            return render(req, "review.html", user=user, reviews=[], error="Недопустимый формат изображения.")

        safe_name = f"{int(datetime.utcnow().timestamp())}_{user.id}{file_ext}"
        file_path = upload_dir / safe_name

        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(photo.file, buffer)

        photo_path = f"/static/uploads/reviews/{safe_name}"

    author_name = user.username or (user.email.split("@")[0] if user.email else "Гость")

    review = Review(
        user_id=user.id,
        author_name=author_name,
        rating=rating,
        text=text,
        photo_path=photo_path,
    )
    session.add(review)
    await session.commit()
    await session.refresh(review)

    await send_review_to_tg(review)

    return RedirectResponse("/review", status_code=303)


@app.post('/admin/review/reply/{review_id}')
async def admin_reply_review(review_id: int, req: Request, session: Session):
    admin = await get_current_user_db(req, session)
    require_admin(admin)

    form = await req.form()
    reply_text = (form.get("reply") or "").strip()

    result = await session.execute(select(Review).where(Review.id == review_id))
    review = result.scalar_one_or_none()

    if not review:
        raise HTTPException(status_code=404, detail="Отзыв не найден")

    review.admin_reply = reply_text or None
    review.admin_reply_at = datetime.utcnow() if reply_text else None
    await session.commit()

    return RedirectResponse("/review", status_code=303)


@app.delete('/admin/review/{review_id}')
async def admin_delete_review(review_id: int, req: Request, session: Session):
    admin = await get_current_user_db(req, session)
    require_admin(admin)

    result = await session.execute(select(Review).where(Review.id == review_id))
    review = result.scalar_one_or_none()

    if not review:
        raise HTTPException(status_code=404, detail="Отзыв не найден")

    await session.delete(review)
    await session.commit()

    return {"success": True}


if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)