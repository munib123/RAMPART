"""ShopFast — payment processing, receipts, merchant webhooks."""
import subprocess

import requests
from lxml import etree

import config


def charge(card_token, amount):
    return requests.post(config.PAYMENT_GATEWAY_URL,
                         data={"token": card_token, "amount": amount, "key": config.PAYMENT_API_KEY},
                         timeout=10)


def generate_receipt(order_id, customer_name):
    """Render an HTML receipt to PDF using the system wkhtmltopdf binary."""
    cmd = f"wkhtmltopdf receipt_{order_id}.html /tmp/receipt_{customer_name}.pdf"
    subprocess.run(cmd, shell=True)


def notify_webhook(callback_url, payload):
    """Merchants register a callback URL that we POST payment events to."""
    return requests.get(callback_url, params=payload, timeout=5)


def parse_bank_response(xml_text):
    """Parse the acquiring bank's XML settlement response."""
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    return etree.fromstring(xml_text.encode(), parser)
