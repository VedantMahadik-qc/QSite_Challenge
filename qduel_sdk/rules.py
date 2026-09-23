"""Versioned public experiment contract. Never infer dimensions from a submitted circuit.

Old stored 0.2 manifests are read without rewriting their JSON or hashes. New
rounds default to the four-qubit measured playtest contract, not the old 80/20 game.
"""
from pydantic import BaseModel, ConfigDict, Field, model_validator
from typing import Literal

CURRENT_RULESET = "quantum-duel-4q-playtest-0.3"
FRAME2_RULESET = "quantum-duel-8q-frame2-0.7"
FRAME4_RULESET = "quantum-duel-8q-frame4-0.7"
FRAME_RULESETS = (FRAME2_RULESET, FRAME4_RULESET)
OPEN8_RULESET = "quantum-duel-8q-open-0.7.1"
EIGHT_QUBIT_RULESETS = (*FRAME_RULESETS, OPEN8_RULESET)
LEGACY_RULESET = "duel-platform-0.2"
ROTATION_GATES = ("rx", "ry", "rz", "rxx", "ryy", "rzz")
LEGACY_GATES = ROTATION_GATES + ("h", "x", "y", "z", "cx")

class Rules(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)
    version: Literal[CURRENT_RULESET, LEGACY_RULESET, FRAME2_RULESET, FRAME4_RULESET, OPEN8_RULESET] = CURRENT_RULESET
    qubits: int = Field(default=4, ge=2, le=8)
    total_shots: int = Field(default=12000, ge=300, le=120000)
    checkpoints: int = Field(default=3, ge=1, le=6)
    max_settings: int = Field(default=180, ge=1, le=1000)
    max_requests: int = Field(default=600, ge=10, le=3000)
    attack_max_gates: int = Field(default=12, ge=1, le=72)
    attack_max_entanglers: int = Field(default=4, ge=1, le=24)
    patch_max_gates: int = Field(default=18, ge=1, le=108)
    patch_max_entanglers: int = Field(default=6, ge=1, le=36)
    good_error: float = Field(default=0.001, gt=0, le=0.5)
    bad_error: float = Field(default=0.1, gt=0, le=1)
    min_attack_error: float = Field(default=0.1, gt=0, le=1)
    scoring_mode: Literal["automated_only", "legacy_human_80_20"] = "automated_only"
    experiment_encoding: Literal["product-pauli-mixed-radix-v1"] = "product-pauli-mixed-radix-v1"

    @model_validator(mode="before")
    @classmethod
    def legacy_defaults(cls, value):
        if isinstance(value, dict) and value.get("version") == LEGACY_RULESET:
            value = dict(value)
            for key, default in {"qubits": 2, "attack_max_entanglers": 2,
                "patch_max_gates": 24, "patch_max_entanglers": 3,
                "scoring_mode": "legacy_human_80_20"}.items():
                value.setdefault(key, default)
        return value

    @model_validator(mode="after")
    def consistent(self):
        if self.total_shots % self.checkpoints:
            raise ValueError("Checkpoints must evenly divide budget")
        if not self.good_error < self.bad_error <= self.min_attack_error:
            raise ValueError("Invalid scoring thresholds")
        if (self.patch_max_gates < self.attack_max_gates or
            self.patch_max_entanglers < self.attack_max_entanglers):
            raise ValueError("Patch budget must contain inverse attack grammar")
        if self.version == CURRENT_RULESET:
            if self.qubits != 4 or self.scoring_mode != "automated_only":
                raise ValueError("The four-qubit playtest uses automated-only scoring")
            if self.attack_max_gates > 12 or self.attack_max_entanglers > 4:
                raise ValueError("Four-qubit attack caps exceeded")
            if self.patch_max_gates > 18 or self.patch_max_entanglers > 6:
                raise ValueError("Four-qubit corrections are capped at 18 gates / 6 entanglers")
        elif self.version in EIGHT_QUBIT_RULESETS:
            expected = dict(qubits=8, attack_max_gates=72, attack_max_entanglers=24,
                patch_max_gates=108, patch_max_entanglers=36, total_shots=96000,
                checkpoints=3, max_settings=720, max_requests=3000,
                good_error=0.001, bad_error=0.1, min_attack_error=0.1,
                scoring_mode="automated_only")
            if any(getattr(self, k) != v for k,v in expected.items()):
                raise ValueError("Eight-qubit profile constants must match the published profile")
        else:
            if self.attack_max_gates > 12 or self.patch_max_gates > 24:
                raise ValueError("Legacy gate caps exceeded")
            if self.qubits != 2 or self.scoring_mode != "legacy_human_80_20":
                raise ValueError("Legacy protocol must retain two qubits and its original scoring")
            if self.attack_max_entanglers > 2 or self.patch_max_entanglers > 3:
                raise ValueError("Legacy entangler caps exceeded")
        return self

    @property
    def block(self): return self.total_shots // self.checkpoints
    @property
    def dimension(self): return 1 << self.qubits
    @property
    def experiment_count(self): return 18 ** self.qubits
    @property
    def alphabet(self):
        return LEGACY_GATES if self.version == LEGACY_RULESET else ROTATION_GATES
    @property
    def max_angle(self):
        import math
        return (8 if self.version == LEGACY_RULESET else 1) * math.pi
    def validation_kwargs(self, purpose="patch"):
        if purpose not in ("patch", "attack"):
            raise ValueError("Unknown circuit purpose")
        return {"n": self.qubits, "max_gates": getattr(self, purpose+"_max_gates"),
                "max_entanglers": getattr(self, purpose+"_max_entanglers"),
                "alphabet": self.alphabet, "max_angle": self.max_angle}
