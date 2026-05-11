import os
import re
import time


DIAGRAM_SYSTEM_PROMPT = """
Voce e um gerador de diagramas para a ferramenta Diagram AI do Vortex.

Regras obrigatorias:

Responda somente com o codigo do diagrama.
Nao use markdown.
Nao use blocos mermaid ou plantuml.
Nao explique nada fora do codigo.
Gere codigo valido para a linguagem solicitada.
Se a linguagem for Mermaid, use sintaxe Mermaid valida.
Se a linguagem for PlantUML, o codigo deve comecar com @startuml e terminar com @enduml.
Use textos curtos e objetivos nos nos.
Para fluxogramas Mermaid, prefira flowchart TD.
Para decisoes, use perguntas curtas.
Para processos tecnicos, mantenha fluxo logico e organizado.
Nao invente dados sensiveis.
Nao gere diagramas gigantes.
""".strip()


MERMAID_STARTERS = (
    "flowchart",
    "graph",
    "sequenceDiagram",
    "classDiagram",
    "stateDiagram",
    "erDiagram",
    "journey",
    "gantt",
    "mindmap",
)


DIAGRAM_TYPE_LABELS = {
    "flowchart": "Fluxograma",
    "sequence": "Sequencia",
    "class": "Classe",
    "state": "Estado",
    "usecase": "Caso de uso",
    "component": "Componentes",
    "er": "ER",
    "mindmap": "Mindmap",
}


def clean_diagram_code(value: str) -> str:
    text = (value or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:mermaid|plantuml|uml)?\s*", "", text, flags=re.I)
        text = re.sub(r"\s*```$", "", text).strip()
    return text


def validate_diagram_code(code: str, language: str) -> None:
    stripped = (code or "").strip()
    if language == "mermaid":
        first = stripped.splitlines()[0].strip() if stripped else ""
        if not any(first.startswith(starter) for starter in MERMAID_STARTERS):
            raise ValueError("A IA nao retornou uma sintaxe Mermaid valida.")
        return

    if language == "plantuml":
        if not stripped.startswith("@startuml") or not stripped.endswith("@enduml"):
            raise ValueError("A IA nao retornou uma sintaxe PlantUML valida.")
        return

    raise ValueError("Linguagem de diagrama invalida.")


def generate_diagram_code(prompt: str, language: str, diagram_type: str) -> str:
    from google import genai
    from google.genai import types

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY nao configurada no ambiente.")

    type_label = DIAGRAM_TYPE_LABELS.get(diagram_type, diagram_type)
    user_content = (
        f"Linguagem: {language}\n"
        f"Tipo de diagrama: {type_label}\n"
        f"Pedido do usuario:\n{prompt}\n\n"
        "Retorne somente o codigo final do diagrama."
    )

    client = genai.Client(api_key=api_key)
    errors = []
    for model in ("gemini-2.5-flash", "gemini-2.5-flash-lite"):
        for attempt in range(2):
            try:
                response = client.models.generate_content(
                    model=model,
                    contents=user_content,
                    config=types.GenerateContentConfig(
                        system_instruction=DIAGRAM_SYSTEM_PROMPT,
                        max_output_tokens=2048,
                        response_mime_type="text/plain",
                        temperature=0.15,
                    ),
                )
                code = clean_diagram_code(response.text)
                validate_diagram_code(code, language)
                return code
            except Exception as exc:
                error_text = str(exc)
                errors.append(f"{model} tentativa {attempt + 1}: {error_text}")
                if attempt == 0 and any(token in error_text for token in ("503", "UNAVAILABLE", "429", "RESOURCE_EXHAUSTED")):
                    time.sleep(2)
                    continue
                break

    raise ValueError("Nao foi possivel gerar o diagrama. Erros: " + " | ".join(errors))
