"""Process orchestration for tests; all applications use the real IPC library."""
import signal
import subprocess
import time
from pathlib import Path


def wait_ready(process, log, marker):
    deadline = time.monotonic() + 20
    while marker not in log.read_text():
        assert process.poll() is None and time.monotonic() < deadline, log.read_text()
        time.sleep(0.01)


class Daemon:
    def __init__(self, binary, config, log, options=()):
        self.clients = []
        self.next_client = 0
        self.streams = []
        self.path = str(config.with_suffix('.sock'))
        daemon = Path(binary).resolve().parent / 'pulsarosd'
        self.process = subprocess.Popen([str(daemon), str(config), '--socket', self.path, *options], stdout=log, stderr=log)
        self.log = Path(log.name)
        try:
            wait_ready(self.process, self.log, 'IPC listening on')
        except BaseException:
            self.stop(check=False)
            raise

    def client(self, binary, port=9000):
        path = self.log.parent / f'client-{self.next_client}.log'
        self.next_client += 1
        stream = path.open('w+')
        self.streams.append(stream)
        process = subprocess.Popen([str(binary), '--socket', self.path, '--port', str(port)], stdout=stream, stderr=stream)
        self.clients.append(process)
        wait_ready(process, path, f'port {port}')
        return process

    def stop_client(self, client, check=True):
        if client.poll() is None:
            client.send_signal(signal.SIGTERM)
        try:
            rc = client.wait(timeout=8)
        except subprocess.TimeoutExpired:
            client.kill()
            client.wait()
            raise
        if check:
            assert rc == 0, [p.read_text() for p in self.log.parent.glob('client-*.log')]

    def stop(self, check=True):
        for client in self.clients:
            self.stop_client(client, check=check)
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
        try:
            rc = self.process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise
        for stream in self.streams:
            stream.close()
        if check:
            assert rc == 0, self.log.read_text()
