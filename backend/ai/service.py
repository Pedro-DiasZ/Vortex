import json
import os
import re

from google import genai
from google.genai import types


def extract_json(text: str) -> dict:
    if not text:
        raise ValueError("Resposta vazia da IA.")

    original_text = text
    text = text.strip()

    # Remove markdown code fences, se existirem.
    if text.startswith("```"):
        text = text.replace("```json", "").replace("```JSON", "").replace("```", "").strip()

    # Primeira tentativa: JSON puro.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Segunda tentativa: extrair objeto JSON entre chaves.
    match = re.search(r"\{[\s\S]*\}", text)

    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    # Terceira tentativa: corrigir escapes comuns problemáticos.
    cleaned = text.replace("\n", "\\n") if "\n" in text and not text.startswith("{") else text

    try:
        return json.loads(cleaned)
    except Exception:
        pass

    raise ValueError(
        "A IA não retornou um JSON válido. Resposta bruta: "
        + original_text[:1000]
    )


def ask_gemini_json(system_prompt: str, user_content: str, max_tokens: int = 1400) -> dict:
    api_key = os.environ.get("GEMINI_API_KEY")

    if not api_key:
        raise ValueError("GEMINI_API_KEY não configurada no ambiente.")

    client = genai.Client(api_key=api_key)

    models = [
        "gemini-2.5-flash",
        "gemini-2.5-flash-lite",
    ]

    errors = []
    strict_user_content = f"""
Responda apenas com JSON válido.
Não use markdown.
Não use bloco ```json.
Não escreva explicações fora do JSON.
O primeiro caractere da resposta deve ser {{ e o último deve ser }}.

Conteúdo para análise:

{user_content}
"""

    for model in models:
        try:
            response = client.models.generate_content(
                model=model,
                contents=strict_user_content,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    max_output_tokens=max_tokens,
                    response_mime_type="application/json",
                ),
            )

            return extract_json(response.text)

        except Exception as e:
            errors.append(f"{model}: {str(e)}")
            continue

    raise ValueError("Não foi possível obter resposta do Gemini. Erros: " + " | ".join(errors))
