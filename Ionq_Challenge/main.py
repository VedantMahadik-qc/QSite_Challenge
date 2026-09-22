def run(client, rules):
    """Cup 1 entry: invert a hidden 4-qubit rotation circuit from measurement counts.

    Uses the public four-qubit ensemble (one-gate pursuit plus conjugated-shell
    groups). That recovers the compact public families; overlapping ladders remain
    hard, so the two submitted attacks use that structure on purpose.
    """
    from qduel_sdk.rules import OPEN8_RULESET
    if rules.version == OPEN8_RULESET:
        from duelkit.recovery8.open_starter import run_defender
        return run_defender(client, rules)
    if rules.qubits == 8:
        from duelkit.recovery8.adapter import run_defender
        return run_defender(client, rules)
    from duelkit.recovery4.adapter import run_defender
    return run_defender(client, rules, grouped=True)
