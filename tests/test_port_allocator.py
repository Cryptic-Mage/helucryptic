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
    assert allocator.current_port == 50001

    # Allocate second port for pc 102
    p2 = allocator.allocate(pc_id=102)
    assert p2 == 50001

    # Pool exhausted -> returns None (seamless fallback to ephemeral)
    p3 = allocator.allocate(pc_id=103)
    assert p3 is None

    # Release pc 101 -> 50000 recycled back to free pool
    allocator.release(101)
    assert allocator.current_port == 50000
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
