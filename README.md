# 🌸 Karinka Flowers

A modern flower shop web application built with **FastAPI**, **MySQL**, and **Jinja2**.

Karinka Flowers allows customers to browse products, place orders, manage their accounts, and leave reviews through a clean and responsive interface.

---

## ✨ Features

- 🌷 Flower & bouquet catalog
- 🛒 Shopping cart
- 📦 Order placement
- 👤 User registration & authentication
- ⭐ Customer reviews
- 📧 Email verification
- 🛠️ Admin dashboard
- 📱 Responsive design
- 🔍 Product search
- 🖼️ Image uploads

---

## 🛠 Tech Stack

### Backend
- FastAPI
- Python 3.13+
- MySQL
- Jinja2

### Frontend
- HTML5
- CSS3
- JavaScript

### Database
- MySQL

---

## 📂 Project Structure

```text
karinka_flowers/
│
├── static/
│   ├── uploads/
│   ├── favicon.ico
│   └── ...
│
├── templates/
│   ├── home.html
│   ├── start.html
│   ├── login.html
│   ├── register.html
│   ├── checkout.html
│   ├── confirm_order.html
│   ├── admin.html
│   ├── about.html
│   └── ...
│
├── models.py
├── server.py
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

Clone the repository

```bash
git clone https://github.com/armen-marg/karinka_flowers.git
cd karinka_flowers
```

Create a virtual environment

```bash
python -m venv venv
```

Windows

```bash
venv\Scripts\activate
```

Linux / macOS

```bash
source venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

Create a `.env` file in the project root and configure your environment variables.

Example:

```env
DB_HOST=localhost
DB_PORT=3306
DB_NAME=karinka_flowers
DB_USER=your_username
DB_PASSWORD=your_password

SECRET_KEY=your_secret_key
```

Run the application

```bash
uvicorn server:app --reload
```

Open your browser

```
http://127.0.0.1:8000
```

---

## 📦 Requirements

- Python 3.13+
- MySQL Server
- pip

---

## 🔒 Security

Sensitive configuration files such as `.env` are **not included** in this repository.

Never commit:

- `.env`
- API keys
- Database credentials
- SMTP passwords
- Secret keys

---

## 📸 Screens

- Home
- Product Catalog
- Shopping Cart
- Checkout
- User Authentication
- Reviews
- About Page
- Admin Panel

---

## 🚀 Deployment

The application can be deployed on:

- Ubuntu VPS
- Nginx
- Gunicorn / Uvicorn
- Docker (optional)

---

## 📄 License

This project was developed for the **Karinka Flowers** flower shop.

---

## 👨‍💻 Author

**Armen Margaryan**

GitHub: https://github.com/armen-marg