import asyncio
import time
from aiohttp import ClientSession
from aiohttp_socks import ProxyConnector

async def fetch(url, session):
    try:
        async with session.get(url) as response:
            return await response.read()
    except Exception as e:
        print(f"Request failed: {e}")
        return None

async def bound_fetch(sem, url, session):
    # Use a semaphore to limit the number of requests
    async with sem:
        return await fetch(url, session)

async def run(r):
    url = "http://example.com"  # Target URL to test against
    tasks = []

    # Replace 'localhost' and '1080' with your proxy's IP and port
    connector = ProxyConnector.from_url('socks5://localhost:1080')

    # Use a semaphore to limit the number of concurrent requests
    sem = asyncio.Semaphore(1000)

    async with ClientSession(connector=connector) as session:
        for i in range(r):
            task = asyncio.ensure_future(bound_fetch(sem, url, session))
            tasks.append(task)

        responses = await asyncio.gather(*tasks)
        print(f"{len([resp for resp in responses if resp is not None])} requests completed successfully.")

if __name__ == "__main__":
    number_of_requests = 100000
    start_time = time.time()
    asyncio.run(run(number_of_requests))
    duration = time.time() - start_time
    print(f"Sent {number_of_requests} requests in {duration} seconds.")
