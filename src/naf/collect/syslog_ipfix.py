"""RFC 5424 syslog parser (implemented) and IPFIX collector interface (planned for v0.5)."""
from __future__ import annotations
import re

_RE = re.compile(r"^<(?P<pri>\d{1,3})>(?P<ver>\d) (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) "
                 r"(?P<procid>\S+) (?P<msgid>\S+) (?P<sd>-|\[.*?\]) ?(?P<msg>.*)$")


def parse_syslog(line: str) -> dict:
    m = _RE.match(line.strip())
    if not m:
        raise ValueError("not an RFC 5424 message")
    pri = int(m["pri"])
    return {"facility": pri // 8, "severity": pri % 8, "timestamp": m["ts"], "host": m["host"],
            "app": m["app"], "msgid": m["msgid"], "message": m["msg"]}


class IpfixCollector:
    """Interface only. A real collector listens on UDP 4739 and decodes IPFIX templates and records."""

    def run(self):  # pragma: no cover
        raise NotImplementedError("IPFIX collection is planned for v0.5")
