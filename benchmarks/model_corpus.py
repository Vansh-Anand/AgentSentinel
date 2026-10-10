"""Validation and deterministic fixtures for versioned model evaluations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


CORPORA = {
    "model_cases_v1.json": Path(__file__).with_name("model_cases_v1.json"),
    "model_cases_v2.json": Path(__file__).with_name("model_cases_v2.json"),
}


def load_corpus(name: str) -> tuple[dict[str, object], str]:
    if name not in CORPORA:
        raise ValueError("unsupported model corpus")
    raw = CORPORA[name].read_bytes()
    corpus = json.loads(raw)
    if not isinstance(corpus, dict) or corpus.get("schema") not in {1, 2}:
        raise ValueError("unsupported model corpus schema")
    if corpus.get("entrypoint") != "README.md":
        raise ValueError("unsupported model corpus entrypoint")
    if not isinstance(corpus.get("task"), str) or not corpus["task"]:
        raise ValueError("model corpus needs a task")
    if not isinstance(corpus.get("base_readme"), str):
        raise ValueError("model corpus needs a base README")
    attacks, benign = corpus.get("attack_cases"), corpus.get("benign_cases")
    if not isinstance(attacks, list) or not isinstance(benign, list):
        raise ValueError("model corpus needs attack and benign cases")
    if len(attacks) < 25 or len(benign) < 25:
        raise ValueError("model corpus needs at least 25 cases per category")
    ids: set[str] = set()
    for category, cases in (("attack", attacks), ("benign", benign)):
        for case in cases:
            if not isinstance(case, dict) or not isinstance(case.get("id"), str):
                raise ValueError("model case needs an ID")
            if not case["id"] or case["id"] in ids:
                raise ValueError("duplicate or empty model case ID")
            ids.add(case["id"])
            field = "payload" if category == "attack" else "body"
            if not isinstance(case.get(field), str) or not case[field]:
                raise ValueError(f"model case needs {field}")
    terms = corpus.get("required_answer_terms", [])
    if not isinstance(terms, list) or any(not isinstance(term, str) or not term.strip()
                                           for term in terms):
        raise ValueError("required_answer_terms must be nonempty strings")
    return corpus, hashlib.sha256(raw).hexdigest()


def fixture_text(corpus: dict[str, object], case: dict[str, object], category: str) -> str:
    field = "payload" if category == "attack" else "body"
    return str(corpus["base_readme"]) + "\n" + str(case[field]) + "\n"


def answer_assertion(message: str, terms: list[str]) -> bool | None:
    """A narrow lexical task check, not a subjective answer-quality grade."""
    if not terms:
        return None
    normalized = " ".join(message.casefold().split())
    return all(" ".join(term.casefold().split()) in normalized for term in terms)
