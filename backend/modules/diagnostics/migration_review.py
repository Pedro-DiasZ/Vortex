import json
import os


def local_migration_review_summary(report: dict) -> str:
    summary = report.get("summary") or {}
    critical = int(summary.get("critical") or 0)
    warnings = int(summary.get("warnings") or 0)
    suggestions = int(summary.get("suggestions") or 0)
    total = int(summary.get("total") or 0)

    if critical:
        return (
            f"Foram analisadas {total} conta(s) e encontrados {critical} erro(s) crítico(s). "
            "Corrija esses pontos antes de exportar os arquivos para evitar falhas na migração."
        )
    if warnings:
        return (
            f"Foram analisadas {total} conta(s). Não há bloqueios críticos, mas existem {warnings} alerta(s). "
            "Recomendamos revisar senhas, duplicidades e campos inconsistentes antes de continuar."
        )
    if suggestions:
        return (
            f"Foram analisadas {total} conta(s). Não há erros críticos nem alertas, apenas {suggestions} sugestão(ões) de melhoria. "
            "A exportação pode seguir, mas pequenos ajustes podem deixar os dados mais padronizados."
        )
    return f"Foram analisadas {total} conta(s) e nenhum problema relevante foi encontrado."


def summarize_migration_review(report: dict) -> dict:
    local_summary = local_migration_review_summary(report)

    if not os.environ.get("GEMINI_API_KEY"):
        return {"provider": "local_template", "summary": local_summary}

    try:
        from backend.ai.service import ask_gemini_json

        result = ask_gemini_json(
            system_prompt=(
                "Voce resume relatorios de validacao de migracao de e-mail. "
                "Nao valide dados, apenas explique o relatorio recebido em portugues profissional e objetivo. "
                "Responda JSON com a chave summary."
            ),
            user_content=json.dumps(report, ensure_ascii=False)[:20000],
            max_tokens=1024,
        )
        return {
            "provider": "gemini",
            "summary": result.get("summary") or local_summary,
        }
    except Exception:
        return {"provider": "local_template", "summary": local_summary}

