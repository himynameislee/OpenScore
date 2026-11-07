"""Scan modules, in execution order. MODE: passive (no contact with target infra),
light (normal-visitor traffic), active (requires --active + written authorization)."""
from . import (discovery, dns_email, exposures, external_tools, ports, reputation, screenshots,
               software, web)

# screenshots runs last so every finding's exhibit can be exported as an image
PIPELINE = [discovery, dns_email, web, reputation, ports, exposures, external_tools, software, screenshots]
