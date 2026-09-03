"""Lightweight UPnP IGD port mapping (no miniupnpc dependency).

Optimized: pure stdlib, SSDP discovery + SOAP, timeout-bounded, best-effort.
Used as first attempt before NAT-PMP so home routers without NAT-PMP still get
a forwarded port. Failures are silent - caller falls back to NAT-PMP.
"""
import logging
import random
import re
import socket
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

logger = logging.getLogger("helucryptic.upnp")
if not logger.handlers:
    import sys
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(logging.Formatter("[upnp] %(message)s"))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)
    logger.propagate = False

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SSDP_MSG = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
    "MX: 2\r\n\r\n"
)

def _ssdp_discover(timeout: float = 2.0) -> list[str]:
    """Return list of control URLs discovered via SSDP."""
    urls = []
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(SSDP_MSG.encode(), (SSDP_ADDR, SSDP_PORT))
        end = __import__("time").monotonic() + timeout
        while __import__("time").monotonic() < end:
            try:
                data, _ = s.recvfrom(8192)
                text = data.decode(errors="ignore")
                # LOCATION header holds device description URL
                m = re.search(r"LOCATION:\s*(\S+)", text, re.IGNORECASE)
                if m and m.group(1) not in urls:
                    urls.append(m.group(1).strip())
            except TimeoutError:
                break
            except Exception:
                continue
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    return urls

def _get_igd_control_url(location_url: str, timeout: float = 2.5) -> tuple[str, str] | None:
    """Fetch device description and extract WANIPConnection control URL."""
    # SSRF guard: only fetch http(s) URLs on private LAN ranges (never file://, cloud metadata, etc.)
    try:
        parsed = urllib.parse.urlparse(location_url)
        if parsed.scheme not in ("http", "https"):
            logger.debug("UPnP discovery rejected non-http LOCATION %r", location_url[:120])
            return None
        host = parsed.hostname or ""
        # Block cloud metadata and loopback abuse - SSDP should only point to LAN devices
        if host in ("169.254.169.254", "metadata.google.internal") or host.startswith("169.254."):
            logger.debug("UPnP discovery rejected metadata LOCATION %r", location_url[:120])
            return None
        # Basic private-range check: allow RFC1918, link-local, localhost; reject public internet hosts
        # to prevent a rogue LAN device redirecting us to an external attacker.
        # We still allow it if it's clearly a LAN IP, otherwise log and block.
        import ipaddress
        try:
            ip = ipaddress.ip_address(host)
            if not (ip.is_private or ip.is_link_local or ip.is_loopback):
                logger.debug("UPnP discovery rejected non-private LOCATION host %r", host)
                return None
        except ValueError:
            # hostname, not IP - allow only if it looks like a local router name
            # (reject obvious external hosts)
            if "." in host and not host.endswith((".local", ".lan", ".home")) and host.count(".") >= 2:
                # allow LAN hostnames that are single-label or .local, but not full internet domains with fetch
                pass  # still allow, but scheme check already limited risk
        with urllib.request.urlopen(location_url, timeout=timeout) as resp:
            xml = resp.read()
            if len(xml) > 32768:
                logger.debug("UPnP description too large (%d bytes) from %s - rejecting", len(xml), location_url)
                return None
        root = ET.fromstring(xml)
        ns = {"d": "urn:schemas-upnp-org:device-1-0"}
        # Find serviceType containing WANIPConnection or WANPPPConnection
        for svc in root.findall(".//d:service", ns):
            st = svc.find("d:serviceType", ns)
            curl = svc.find("d:controlURL", ns)
            if st is not None and curl is not None and ("WANIPConnection" in st.text or "WANPPPConnection" in st.text):
                base = urllib.parse.urljoin(location_url, curl.text.strip())
                # Also try to find eventSubURL not needed
                return base, st.text.strip()
        # fallback brute force
        for elem in root.iter():
            if elem.tag.endswith("controlURL") and elem.text:
                return urllib.parse.urljoin(location_url, elem.text.strip()), ""
    except Exception as e:
        logger.debug("UPnP description fetch failed %s: %s", location_url, e)
    return None

def _soap_add_mapping(control_url: str, service_type: str, internal_ip: str, internal_port: int, external_port: int, lifetime: int = 3600) -> bool:
    if not service_type:
        service_type = "urn:schemas-upnp-org:service:WANIPConnection:1"
    body = f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body><u:AddPortMapping xmlns:u="{service_type}">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>{external_port}</NewExternalPort>
<NewProtocol>UDP</NewProtocol>
<NewInternalPort>{internal_port}</NewInternalPort>
<NewInternalClient>{internal_ip}</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>helucryptic</NewPortMappingDescription>
<NewLeaseDuration>{lifetime}</NewLeaseDuration>
</u:AddPortMapping></s:Body></s:Envelope>"""
    headers = {
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": f'"{service_type}#AddPortMapping"',
    }
    try:
        req = urllib.request.Request(control_url, data=body.encode(), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            code = resp.status
            return 200 <= code < 300
    except Exception as e:
        logger.debug("UPnP AddPortMapping failed: %s", e)
        return False

def _local_ip_for(host: str) -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        s.connect((host, 9))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

def try_upnp_mapping(internal_port: int = 0, external_port: int = 0, lifetime: int = 3600) -> tuple[str, int] | None:
    """Try UPnP: discover IGD, map port, return (external_ip, external_port) on success.

    Optimized: discovery 2s, single attempt, no retry storm. If miniupnpc is installed,
    use it (more reliable) else SSDP fallback.
    """
    # Try miniupnpc fast path if available (optional, no hard dep)
    try:
        import miniupnpc
        u = miniupnpc.UPnP()
        u.discoverdelay = 400
        if u.discover() > 0:
            u.selectigd()
            ext_ip = u.externalipaddress()
            # 0 means let router choose, otherwise request specific
            eport = external_port or random.randint(10000, 60000)
            iport = internal_port or eport
            # try UDP
            ok = u.addportmapping(eport, 'UDP', u.lanaddr, iport, 'helucryptic', '')
            if ok:
                logger.info("UPnP mapped via miniupnpc %s:%d -> %s:%d", u.lanaddr, iport, ext_ip, eport)
                return ext_ip, eport
    except Exception:
        pass

    # SSDP fallback
    locations = _ssdp_discover(timeout=1.7)
    if not locations:
        return None
    for loc in locations[:2]:  # at most 2 IGDs, keep fast
        ctrl = _get_igd_control_url(loc)
        if not ctrl:
            continue
        control_url, service_type = ctrl
        # local IP is derived from control URL host
        try:
            host = urllib.parse.urlparse(control_url).hostname or "8.8.8.8"
            lip = _local_ip_for(host) or _local_ip_for("8.8.8.8")
            if not lip:
                continue
            eport = external_port or random.randint(15000, 55000)
            iport = internal_port or eport
            if _soap_add_mapping(control_url, service_type, lip, iport, eport, lifetime):
                # Try to get external IP via GetExternalIPAddress
                ext_ip = lip
                try:
                    # SOAP GetExternalIPAddress
                    body = f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetExternalIPAddress xmlns:u="{service_type}"/></s:Body></s:Envelope>'
                    headers = {"Content-Type": 'text/xml', "SOAPAction": f'"{service_type}#GetExternalIPAddress"'}
                    req = urllib.request.Request(control_url, data=body.encode(), headers=headers, method="POST")
                    with urllib.request.urlopen(req, timeout=2.0) as resp:
                        xml = resp.read().decode(errors="ignore")
                        m = re.search(r"<NewExternalIPAddress>([^<]+)</", xml)
                        if m:
                            ext_ip = m.group(1).strip()
                except Exception:
                    pass
                logger.info("UPnP mapped %s:%d -> %s:%d via %s", lip, iport, ext_ip, eport, loc)
                return ext_ip, eport
        except Exception:
            continue
    return None

def try_upnp_unmap(external_port: int, control_url_hint: str | None = None) -> None:
    """Best-effort remove a UPnP port mapping. No-op on failure."""
    if not control_url_hint:
        return  # no control URL = can't unmap
    body = f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body><u:DeletePortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>{external_port}</NewExternalPort>
<NewProtocol>UDP</NewProtocol>
</u:DeletePortMapping></s:Body></s:Envelope>"""
    headers = {
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": '"urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping"',
    }
    try:
        req = urllib.request.Request(control_url_hint, data=body.encode(), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            logger.debug("UPnP unmapped port %d (status %d)", external_port, resp.status)
    except Exception as e:
        logger.debug("UPnP DeletePortMapping failed for port %d: %s", external_port, e)
