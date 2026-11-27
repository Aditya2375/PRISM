"""A slow command must not stall the event loop: health and operator reads stay responsive meanwhile."""
import asyncio
import time

import httpx

from kig.api import create_app
from kig.client import Device
from kig.service import GuardService
from conftest import Clock


def test_health_answers_while_a_command_is_busy(tmp_path):
    clock = Clock()
    svc = GuardService(tmp_path / "d", clock=clock)
    clock.tick(1)
    d = Device.generate("admin-1", "root")
    svc.bootstrap("root", "admin-1", d.sign_pub, d.kem_pub)
    app = create_app(tmp_path / "d", svc)
    real = svc.handle

    def slow(env, source="local"):
        time.sleep(0.6)                      # stands in for signing, fsync and a large ciphertext
        return real(env, source)

    svc.handle = slow
    token = (tmp_path / "d" / "operator.token").read_text().strip()

    async def go():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
            busy = asyncio.create_task(c.post("/v1/command", content=b'{"x":1}'))
            t0 = time.perf_counter()
            await asyncio.sleep(0.1)
            r = await c.get("/v1/overview", headers={"X-KIG-Operator-Token": token})
            took = time.perf_counter() - t0
            await busy
            return r.status_code, took

    status, took = asyncio.run(go())
    assert status == 200
    assert took < 0.45, f"operator read waited {took:.2f}s behind a busy command"
