import os

from fastapi import HTTPException


def validate_ai_token(data: dict):
    expected_token = os.environ.get("AI_ACCESS_TOKEN")

    if not expected_token:
        raise HTTPException(
            status_code=500,
            detail="AI_ACCESS_TOKEN não configurado no servidor."
        )

    received_token = (
        data.get("ai_token")
        or data.get("token")
        or data.get("access_token")
        or ""
    )

    if not received_token:
        raise HTTPException(
            status_code=403,
            detail="Token de acesso da IA não informado."
        )

    if received_token != expected_token:
        raise HTTPException(
            status_code=403,
            detail="Token de acesso da IA inválido."
        )

    return True
