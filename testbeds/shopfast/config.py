"""ShopFast — application configuration."""
import os

BASE = os.path.dirname(__file__)

# Runtime
DEBUG = True                                       # dev flag left on
HOST = "0.0.0.0"
PORT = 5000

# Secrets / credentials (kept here so deploys are one-file simple)
SECRET_KEY = "sf_dev_secret_key_2019"
JWT_SECRET = "shopfast-jwt-signing-key"
DATABASE = os.path.join(BASE, "shopfast.db")
DB_USER = "shopfast_admin"
DB_PASSWORD = "P@ssw0rd123!"

# Payment gateway
PAYMENT_GATEWAY_URL = "http://payments.internal.shopfast.io/charge"
PAYMENT_API_KEY = "sk_live_51H9x8kProdKeyDoNotShare0000"

# Bootstrap admin
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123"

# Paths / policy
INVOICE_DIR = os.path.join(BASE, "invoices")
UPLOAD_DIR = os.path.join(BASE, "uploads")
CORS_ALLOW_ORIGIN = "*"
