from fastapi import FastAPI, Request, Depends
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import os
from dotenv import load_dotenv
from pathlib import Path
import uvicorn
import smtplib
from email.mime.text import MIMEText
from random import randint
from datetime import datetime, timedelta, timezone
from argon2 import PasswordHasher
from database import get_session, engine
from models import Base, Users
from typing import Annotated
from authx import AuthX, AuthXConfig
from fastapi.responses import RedirectResponse
from contextlib import asynccontextmanager

# =========== SETTINGS ==============
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=BASE_DIR / "templates")

load_dotenv()

ph = PasswordHasher()

sender = os.getenv("MY_GMAIL")
email_password = os.getenv("MY_PASSWORD")

CODE_LIFETIME_MINUTES = 10

Session = Annotated[AsyncSession, Depends(get_session)]

config = AuthXConfig(
    JWT_SECRET_KEY=os.getenv("TOP_SECRET_KEY"),
    JWT_ACCESS_COOKIE_NAME="My_access_Cookie",
    JWT_DECODE_ALGORITHMS=["HS256"],
)
auth = AuthX(config=config)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(title="Karinka Flowers Shop", lifespan=lifespan)


# =========== HELPERS ==================

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib


def send_verification_email(to_email: str, code: str) -> bool:
    if not sender or not email_password:
        print("MY_GMAIL или MY_PASSWORD не заданы")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Подтверждение регистрации — Karinka Flowers"
    msg["From"] = sender
    msg["To"] = to_email

    html = f"""
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

            <p>
                Ваш код подтверждения:
            </p>

            <div style="
                font-size:40px;
                font-weight:bold;
                letter-spacing:10px;
                color:#e91e63;
                margin:20px 0;
            ">
                {code}
            </div>

            <p>
                Код действителен {CODE_LIFETIME_MINUTES} минут.
            </p>

            <p style="color:gray;font-size:12px;">
                Если вы не регистрировались на сайте,
                просто проигнорируйте это письмо.
            </p>
        </div>
    </body>
    </html>
    """

    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(sender, email_password)
            smtp.sendmail(sender, to_email, msg.as_string())

        print(f"Email успешно отправлен на {to_email}")
        return True

    except Exception as e:
        print(f"Ошибка отправки email: {e}")
        return False
def generate_code() -> str:
    return str(randint(100000, 999999))


# =========== APP ==================

@app.get('/')
async def logo(req: Request):
    return templates.TemplateResponse(request=req, name="logo.html", context={})


@app.get('/enter')
async def enter(req: Request):
    try:
        token = await auth.get_token_from_request(req)
        auth.verify_token(token=token, verify_csrf=False)
        return RedirectResponse("/start", status_code=303)
    except Exception:
        return RedirectResponse("/home", status_code=303)


@app.get('/home')
async def home(req: Request):
    return templates.TemplateResponse(request=req, name="home.html", context={})


@app.get('/register')
async def register_page(req: Request):
    return templates.TemplateResponse(request=req, name="register.html", context={})


@app.post('/register')
async def register(req: Request, session: Session):
    form = await req.form()

    username = form.get("name")
    email = form.get("email")
    password = form.get("password")
    confirm = form.get("confirm_password")

    if not username or not email or not password or not confirm:
        return templates.TemplateResponse(
            request=req,
            name="register.html",
            context={"error": "Заполните все поля!"},
        )

    if password != confirm:
        return templates.TemplateResponse(
            request=req,
            name="register.html",
            context={"error": "Пароли не совпадают!"},
        )

    result = await session.execute(select(Users).where(Users.email == email))
    existing_user = result.scalar_one_or_none()

    if existing_user and existing_user.is_verified:
        return templates.TemplateResponse(
            request=req,
            name="register.html",
            context={"error": "Пользователь с таким email уже существует!"},
        )

    hashed_password = ph.hash(password)
    code = generate_code()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=CODE_LIFETIME_MINUTES)

    if existing_user and not existing_user.is_verified:
        # уже пытался регаться, но код не подтвердил — обновляем данные
        existing_user.username = username
        existing_user.password = hashed_password
        existing_user.verification_code = code
        existing_user.code_expires_at = expires_at
    else:
        new_user = Users(
            username=username,
            email=email,
            password=hashed_password,
            is_verified=False,
            verification_code=code,
            code_expires_at=expires_at,
        )
        session.add(new_user)

    await session.commit()

    send_verification_email(email, code)

    return RedirectResponse(url=f"/verify-email?email={email}", status_code=303)


@app.get('/verify-email')
async def verify_email_page(req: Request, email: str):
    return templates.TemplateResponse(
        request=req,
        name="verify_email.html",
        context={"email": email},
    )


@app.post('/verify-email')
async def verify_email(req: Request, session: Session):
    form = await req.form()
    email = form.get("email")
    code = form.get("code")

    if not email or not code:
        return templates.TemplateResponse(
            request=req,
            name="verify_email.html",
            context={"email": email, "error": "Введите код подтверждения!"},
        )

    result = await session.execute(select(Users).where(Users.email == email))
    user = result.scalar_one_or_none()

    if not user:
        return RedirectResponse(url="/register", status_code=303)

    if user.is_verified:
        return RedirectResponse(url="/home", status_code=303)

    if user.code_expires_at < datetime.utcnow():
        return templates.TemplateResponse(
            request=req,
            name="verify_email.html",
            context={"email": email, "error": "Код устарел, запросите новый."},
        )

    if user.verification_code != code:
        return templates.TemplateResponse(
            request=req,
            name="verify_email.html",
            context={"email": email, "error": "Неверный код."},
        )

    user.is_verified = True
    user.verification_code = None
    user.code_expires_at = None
    await session.commit()

    token = auth.create_access_token(uid=email)
    response = RedirectResponse(url="/start", status_code=303)
    auth.set_access_cookies(token=token, response=response)

    return response


@app.post('/verify-email/resend')
async def resend_code(req: Request, session: Session):
    form = await req.form()
    email = form.get("email")

    result = await session.execute(select(Users).where(Users.email == email))
    user = result.scalar_one_or_none()

    if not user or user.is_verified:
        return RedirectResponse(url="/home", status_code=303)

    code = generate_code()
    user.verification_code = code
    user.code_expires_at = datetime.now(timezone.utc) + timedelta(minutes=CODE_LIFETIME_MINUTES)
    await session.commit()

    send_verification_email(email, code)

    return templates.TemplateResponse(
        request=req,
        name="verify_email.html",
        context={"email": email, "info": "Новый код отправлен на почту."},
    )


@app.get('/start')
async def start(req: Request):
    try:
        token = await auth.get_token_from_request(req)
        payload = auth.verify_token(token=token, verify_csrf=False)
    except Exception:
        return RedirectResponse("/home", status_code=303)

    return templates.TemplateResponse(request=req, name="start.html", context={"user": payload})


if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)