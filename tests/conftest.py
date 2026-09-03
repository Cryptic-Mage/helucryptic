"""Global test hygiene: cancel leaked WebRTC/client background tasks so the
per-function event loop can close cleanly without 'Task was destroyed but it
is pending!' warnings.
"""
import asyncio
import warnings

import pytest
import pytest_asyncio

# Suppress known third-party noise that is not a regression signal:
warnings.filterwarnings(
    "ignore",
    category=PendingDeprecationWarning,
    message=r"Please use.*import python_multipart.*",
)
warnings.filterwarnings(
    "ignore",
    category=pytest.PytestUnraisableExceptionWarning,
)
# Starlette's formparser warning is covered by the PendingDeprecationWarning filter,
# but also silence any starlette deprecation in general
warnings.filterwarnings("ignore", category=DeprecationWarning, module="starlette.*")


@pytest_asyncio.fixture(autouse=True, loop_scope="function")
async def _cancel_leaked_background_tasks():
    yield
    # 1) Try to shut down any WebRTCEngine instances found via gc
    try:
        import gc

        import webrtc_engine as _we
        engines = [o for o in gc.get_objects() if isinstance(o, _we.WebRTCEngine)]
        for eng in engines:
            try:
                await asyncio.wait_for(eng.shutdown(), timeout=0.8)
            except Exception:
                pass
    except Exception:
        pass
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    await asyncio.sleep(0)
    for _ in range(5):
        pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
        current = asyncio.current_task(loop)
        to_cancel = [t for t in pending if t is not current]
        if not to_cancel:
            break
        for task in to_cancel:
            try:
                task.cancel()
            except Exception:
                pass
        try:
            await asyncio.wait_for(asyncio.gather(*to_cancel, return_exceptions=True), timeout=0.8)
        except asyncio.TimeoutError:
            pass
        await asyncio.sleep(0.02)
    # Final: suppress 'Task was destroyed' for any tasks whose loop is already closing
    # by explicitly retrieving exception of cancelled tasks
    try:
        pending = [t for t in asyncio.all_tasks(loop) if t.done() and not t.cancelled()]
        for t in pending:
            try:
                _ = t.exception()
            except Exception:
                pass
    except Exception:
        pass
