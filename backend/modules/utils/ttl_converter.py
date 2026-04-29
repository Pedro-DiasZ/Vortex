def ttl_seconds_to_human(seconds: int):
    try:
        total_seconds = int(seconds)
    except (TypeError, ValueError):
        return {"found": False, "status": "Invalid seconds value"}

    if total_seconds < 0:
        return {"found": False, "status": "Seconds must be zero or positive"}

    units = [
        ("day", 86400),
        ("hour", 3600),
        ("minute", 60),
        ("second", 1)
    ]

    remaining = total_seconds
    parts = []

    for name, size in units:
        qty, remaining = divmod(remaining, size)
        if qty:
            suffix = "" if qty == 1 else "s"
            parts.append(f"{qty} {name}{suffix}")

    human_readable = ", ".join(parts) if parts else "0 seconds"

    return {
        "found": True,
        "seconds": total_seconds,
        "human_readable": human_readable
    }
