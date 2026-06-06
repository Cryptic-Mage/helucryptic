NATPMP_PORT = 5351
OP_MAP_UDP = 1
OP_MAP_TCP = 2

# Proton VPN's NAT-PMP gateway is reliably 10.2.0.1; used as a fallback if
# gateway derivation fails.
PROTON_GATEWAY = ".".join(["10", "2", "0", "1"])
