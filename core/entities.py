from dataclasses import dataclass, field
from typing import List, Set, Dict


@dataclass
class PolicyStatement:
    effect: str
    actions: Set[str]
    resources: Set[str]


@dataclass
class Principal:
    name: str
    account_id: str
    type: str  # "user" or "role"

    policy_statements: List[PolicyStatement] = field(default_factory=list)
    trusts: Set[str] = field(default_factory=set)
    arn: str = None


    attached_managed_policies: List[Dict] = field(default_factory=list)

    def __hash__(self):
        return hash(self.name)