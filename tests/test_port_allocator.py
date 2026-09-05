import threading

from webrtc_engine import PortPoolAllocator


def test_port_pool_allocator_basic_lifecycle():
    allocator = PortPoolAllocator()
    assert not allocator.is_active
    assert allocator.vpn_ip is None
    assert allocator.current_port == 0

    allocator.configure("10.2.0.5", [50000, 50001])
    assert allocator.is_active
    assert allocator.vpn_ip == "10.2.0.5"
    assert allocator.current_port == 50000

    # Allocate first port for pc 101
    p1 = allocator.allocate(pc_id=101)
    assert p1 == 50000
    # current_port names the port to ADVERTISE in the injected srflx candidate,
    # so it stays pinned to the primary forwarded port while that port is
    # checked out. Tracking the free-list head instead made the SDP advertise a
    # port nothing was bound to, and 0 once the pool drained.
    assert allocator.current_port == 50000

    # Allocate second port for pc 102
    p2 = allocator.allocate(pc_id=102)
    assert p2 == 50001

    # Pool exhausted -> returns None (seamless fallback to ephemeral)
    p3 = allocator.allocate(pc_id=103)
    assert p3 is None

    # Release pc 101 -> 50000 recycled back to free pool
    allocator.release(101)
    p4 = allocator.allocate(pc_id=104)
    assert p4 == 50000

    # Clear disables active state and frees allocations
    allocator.clear()
    assert not allocator.is_active
    assert allocator.allocate() is None


def test_port_pool_allocator_concurrency():
    allocator = PortPoolAllocator()
    ports = list(range(40000, 40100))
    allocator.configure("10.0.0.1", ports)

    allocated_results = []
    lock = threading.Lock()

    def worker(worker_id):
        port = allocator.allocate(pc_id=worker_id)
        if port is not None:
            with lock:
                allocated_results.append(port)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(150)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly 100 ports should be allocated without duplicates
    assert len(allocated_results) == 100
    assert len(set(allocated_results)) == 100


def test_configure_collapses_duplicate_natpmp_ports():
    """NAT-PMP returns the SAME external port for every request in the pool.

    Binding one port twice fails with EADDRINUSE, so the duplicates the manager
    publishes must never become two allocatable slots.
    """
    allocator = PortPoolAllocator()
    allocator.configure("10.2.0.2", [54097, 54097, 54097])
    assert allocator.current_port == 54097
    assert allocator.allocate(pc_id=1) == 54097
    assert allocator.allocate(pc_id=2) is None


def test_configure_is_a_noop_for_an_unchanged_mapping():
    """The renewal loop republishes every ~45s while calls are live.

    Re-running configure() there would hand a connected peer's port back out and
    wipe the bookkeeping that releases it.
    """
    allocator = PortPoolAllocator()
    allocator.configure("10.2.0.2", [54097])
    assert allocator.allocate(pc_id=1) == 54097

    allocator.configure("10.2.0.2", [54097])          # renewal, same mapping
    assert allocator.allocate(pc_id=2) is None        # still checked out

    # A genuinely new mapping does reset the pool.
    allocator.configure("10.2.0.2", [54098])
    assert allocator.current_port == 54098
    assert allocator.allocate(pc_id=3) == 54098


def test_release_port_by_value_refills_the_pool():
    """The bind wrapper releases by port, since it never sees the pc."""
    allocator = PortPoolAllocator()
    allocator.configure("10.2.0.2", [54097])
    assert allocator.allocate() == 54097
    assert allocator.allocate() is None

    allocator.release_port(54097)
    assert allocator.allocate() == 54097

    # Releasing twice must not duplicate the slot, and a port that was never
    # part of the mapping is ignored.
    allocator.release_port(54097)
    allocator.release_port(54097)
    allocator.release_port(9999)
    assert allocator.allocate() == 54097
    assert allocator.allocate() is None


# ---------------------------------------------------------------------------
# The bind wrapper: aioice asks for (vpn_ip, 0) and must come back bound to the
# forwarded port, then hand that port back when the socket closes.
# ---------------------------------------------------------------------------

class _FakeTransport:
    def __init__(self, local_addr):
        self.local_addr = local_addr
        self.closed = False

    def close(self):
        self.closed = True


def _wrapper_over(binds, fail_ports=()):
    """A bind wrapper over a fake create_datagram_endpoint recording each bind."""
    import webrtc_engine as we

    async def orig(protocol_factory, *args, local_addr=None, **kwargs):
        binds.append(local_addr)
        if local_addr and local_addr[1] in fail_ports:
            raise OSError(48, "Address already in use")
        return _FakeTransport(local_addr), object()

    return we._make_bind_wrapper(orig)


def test_bind_wrapper_uses_forwarded_port_and_releases_it_on_close():
    import asyncio

    import webrtc_engine as we

    we._port_allocator.configure("10.2.0.2", [54097])
    try:
        binds = []
        wrapped = _wrapper_over(binds)
        transport, _ = asyncio.run(wrapped(None, local_addr=("10.2.0.2", 0)))
        assert binds == [("10.2.0.2", 54097)]

        # While the socket lives the port stays checked out...
        assert we._port_allocator.allocate() is None
        # ...and closing it returns the port, so the next ICE restart is not
        # silently downgraded to an ephemeral (unreachable) port.
        transport.close()
        assert transport.closed
        assert we._port_allocator.allocate() == 54097
    finally:
        we._port_allocator.clear()


def test_bind_wrapper_falls_back_to_ephemeral_when_port_is_busy():
    import asyncio

    import webrtc_engine as we

    we._port_allocator.configure("10.2.0.2", [54097])
    try:
        binds = []
        wrapped = _wrapper_over(binds, fail_ports={54097})
        asyncio.run(wrapped(None, local_addr=("10.2.0.2", 0)))
        # Retried on an ephemeral port rather than failing the whole gather.
        assert binds == [("10.2.0.2", 54097), ("10.2.0.2", 0)]
        # And the port went back to the pool instead of leaking.
        assert we._port_allocator.allocate() == 54097
    finally:
        we._port_allocator.clear()


def test_bind_wrapper_leaves_other_addresses_alone():
    import asyncio

    import webrtc_engine as we

    we._port_allocator.configure("10.2.0.2", [54097])
    try:
        binds = []
        wrapped = _wrapper_over(binds)
        # A LAN interface bind must not steal the VPN's forwarded port.
        asyncio.run(wrapped(None, local_addr=("192.168.1.5", 0)))
        assert binds == [("192.168.1.5", 0)]
        assert we._port_allocator.allocate() == 54097
    finally:
        we._port_allocator.clear()
