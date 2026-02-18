from dataclasses import dataclass, field
from typing import Set


@dataclass
class Principal:
    name: str
    type: str  # "user" or "role"
    allow_actions: Set[str] = field(default_factory=set)
    deny_actions: Set[str] = field(default_factory=set)
    trusts: Set[str] = field(default_factory=set)

    def __hash__(self):
        return hash(self.name)
