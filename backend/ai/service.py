import json
import os
import re
import time

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

    if text.startswith("{") and not text.endswith("}"):
        raise ValueError(
            "A IA retornou um JSON incompleto, provavelmente por limite de tokens ou interrupção na geração. "
            "Resposta parcial: " + original_text[:500]
        )

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
        + original_text[:500]
    )


def ask_gemini_json(system_prompt: str, user_content: str, max_tokens: int = 4096) -> dict:
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

Seja objetivo.
Limite cada descrição a no máximo 2 frases.
Limite a explicação técnica a no máximo 6 frases.
Limite a resposta ao cliente a no máximo 3 parágrafos curtos.
Não repita informações desnecessárias.

Conteúdo para análise:

{user_content}
"""

    for model in models:
        for attempt in range(2):
            try:
                response = client.models.generate_content(
                    model=model,
                    contents=strict_user_content,
                    config=types.GenerateContentConfig(
                        system_instruction=system_prompt,
                        max_output_tokens=max_tokens,
                        response_mime_type="application/json",
                        temperature=0.2,
                    ),
                )

                return extract_json(response.text)

            except Exception as e:
                error_text = str(e)
                errors.append(f"{model} tentativa {attempt + 1}: {error_text}")

                if attempt == 0 and (
                    "503" in error_text
                    or "UNAVAILABLE" in error_text
                    or "429" in error_text
                    or "RESOURCE_EXHAUSTED" in error_text
                ):
                    time.sleep(2)
                    continue

                break

    raise ValueError("Não foi possível obter resposta do Gemini. Erros: " + " | ".join(errors))
