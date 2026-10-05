"""probe-flow XML: parser flags decide XXE."""
from lxml import etree


def parse_partner_feed(xml_bytes):
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(xml_bytes, parser)


def parse_partner_feed_safe(xml_bytes):
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    return etree.fromstring(xml_bytes, parser)
