from sqlalchemy import Float, ForeignKey, String, Text, Integer, DateTime, func, Boolean, Column
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from datetime import datetime


class Base(DeclarativeBase):
    pass


class Users(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer(), primary_key=True, autoincrement=True)

    username: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    password: Mapped[str] = mapped_column(Text(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    verification_code: Mapped[str | None] = mapped_column(String(20), nullable=True)
    code_expires_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_verified = Column(Boolean, default=False, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    is_banned = Column(Boolean, default=False, nullable=False)


class Flower(Base):
    __tablename__ = "flowers"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    price: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    image_path: Mapped[str] = mapped_column(String(300), nullable=False)
    stock: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class Order(Base):
    """Заказ.

    Поддерживает 2 режима, чтобы не ломать старые данные и старый эндпоинт /order/{id}:

    1) Legacy / одиночный товар: flower_id и quantity заполнены напрямую на Order
       (как было раньше). items у такого заказа будет пустым.

    2) Корзина / мультитовар (новый /checkout): flower_id и quantity на Order
       остаются NULL, а товары лежат в order.items (список OrderItem).

    При отображении заказа сначала проверяйте order.items — если там что-то есть,
    это мультитоварный заказ, иначе используйте order.flower_id/order.quantity
    как раньше.
    """
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # nullable теперь: для мультитоварных заказов эти поля не используются
    flower_id = Column(Integer, ForeignKey("flowers.id"), nullable=True)
    quantity = Column(Integer, nullable=True, default=1)

    customer_name = Column(String(100), nullable=False)
    phone = Column(String(50), nullable=False)
    address = Column(String(255), nullable=False)
    comment = Column(Text, default="")
    payment_method = Column(String(20), nullable=False)  # cash / card

    # итоговая сумма заказа (товары + доставка), одна на весь заказ
    price: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    delivery_fee: Mapped[float] = mapped_column(Float, nullable=False, default=0)

    status = Column(String(20), nullable=False, default="new")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("Users")
    flower = relationship("Flower")  # используется только в legacy-заказах

    items = relationship(
        "OrderItem",
        back_populates="order",
        cascade="all, delete-orphan",
    )

    payment = relationship(
        "Payment",
        back_populates="order",
        uselist=False
    )


class OrderItem(Base):
    """Одна позиция в мультитоварном заказе (одна строка корзины)."""
    __tablename__ = "order_items"

    id = Column(Integer, primary_key=True, index=True)
    order_id = Column(Integer, ForeignKey("orders.id"), nullable=False)
    flower_id = Column(Integer, ForeignKey("flowers.id"), nullable=False)

    quantity = Column(Integer, nullable=False, default=1)

    # цена за штуку на момент покупки — чтобы изменение цены цветка в каталоге
    # не искажало задним числом сумму уже сделанных заказов
    unit_price: Mapped[float] = mapped_column(Float, nullable=False, default=0)

    order = relationship("Order", back_populates="items")
    flower = relationship("Flower")

    @property
    def line_total(self) -> float:
        return (self.unit_price or 0) * (self.quantity or 0)


class Review(Base):
    __tablename__ = "reviews"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    author_name = Column(String(50), nullable=False)

    rating = Column(Integer, nullable=False, default=5)
    text = Column(Text, nullable=False)

    photo_path = Column(Text, nullable=True)

    admin_reply = Column(Text, nullable=True)
    admin_reply_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("Users", backref="reviews")


class Card(Base):
    __tablename__ = "cards"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    brand = Column(String(20), nullable=False, default="card")  # visa / mastercard / mir / card
    last4 = Column(String(4), nullable=False)
    holder_name = Column(String(100), nullable=False)
    exp_month = Column(Integer, nullable=False)
    exp_year = Column(Integer, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("Users", backref="cards")


class Payment(Base):
    __tablename__ = "payments"

    id = Column(Integer, primary_key=True, index=True)

    order_id = Column(Integer, ForeignKey("orders.id"), nullable=False)
    provider = Column(String(50), nullable=False)
    payment_id = Column(String(255), nullable=True)
    transaction_id = Column(String(255), nullable=True)
    amount = Column(Float, nullable=False)
    currency = Column(String(10), default="AMD")
    status = Column(String(30), default="pending")
    payment_url = Column(Text, nullable=True)
    bank_response = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    order = relationship("Order", back_populates="payment")