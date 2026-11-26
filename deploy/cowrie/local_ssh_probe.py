"""Make three synthetic SSH authentication attempts against local Cowrie.

Run this file through ``docker exec -i`` so the client remains on Cowrie's
loopback interface and does not require publishing a container port. The
username and password are generated in memory, are never printed, and are only
used to produce Cowrie test events.
"""

from __future__ import annotations

import secrets

from twisted.conch.ssh import connection, transport, userauth
from twisted.internet import defer, protocol, reactor


username = "placement-lab-" + secrets.token_hex(4)
password = secrets.token_urlsafe(24)


class ProbeConnection(connection.SSHConnection):
    def serviceStarted(self) -> None:
        # Close immediately after the fake honeypot login succeeds. No shell
        # channel or command is requested.
        reactor.callLater(0, self.transport.transport.loseConnection)


class ProbeAuth(userauth.SSHUserAuthClient):
    preferredOrder = [b"password"]

    def getPassword(self, prompt=None):
        return defer.succeed(password.encode("utf-8"))


class ProbeTransport(transport.SSHClientTransport):
    def verifyHostKey(self, hostKey, fingerprint):
        # The process connects only to 127.0.0.1 inside Cowrie's own container.
        return defer.succeed(True)

    def connectionSecure(self) -> None:
        self.requestService(ProbeAuth(username.encode("utf-8"), ProbeConnection()))


class ProbeFactory(protocol.ClientFactory):
    protocol = ProbeTransport
    remaining = 3
    completed = 0

    def start_next(self) -> None:
        if self.remaining <= 0:
            reactor.stop()
            return
        self.remaining -= 1
        reactor.connectTCP("127.0.0.1", 2222, self)

    def clientConnectionLost(self, connector, reason) -> None:
        self.completed += 1
        reactor.callLater(0.25, self.start_next)

    def clientConnectionFailed(self, connector, reason) -> None:
        print("local_probe_connection_failed", flush=True)
        reactor.stop()


factory = ProbeFactory()
reactor.callLater(15, reactor.stop)
reactor.callLater(0, factory.start_next)
reactor.run()
print("local_probe_sessions_completed", factory.completed, flush=True)
