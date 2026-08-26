"""A model naming a real method in the wrong dialect must not lose its interpretation.

Measured on a live Gemini run over a corpus sample. The catalogue offers JVM-descriptor
signatures:

    Lcom/b/a/c/a;->a(android.content.Context,java.lang.String)

and the model answered about exactly that method, written the way a human writes it:

    com.b.a.c.a->a(android.content.Context, String)

The lookup was an exact dict hit, so all three interpretations produced in that run were
dropped with `interpretation_for_unknown_method`, and the dashboard reported
`0 methods interpreted` for the flagship reverse-engineering layer. The model had done
the work; the matcher threw it away.

The fix must stay strict about the thing that matters. Dropping an interpretation for a
method we never recovered is deliberate — it is the same discipline as rejecting an
ungrounded citation (CLAUDE.md rule 5), and it must keep working. What is relaxed is only
the *spelling* of a method we did recover: package separator, the `L…;` wrapper, spacing,
and whether parameter types are written short or fully qualified.
"""

from __future__ import annotations

import pytest

from drishti.m4_genai.agents.code_interpreter import canonical_signature, resolve_signature

# What the retrieval catalogue ACTUALLY stores, verified against a live pack: class and
# method name, no parameter list.
CATALOGUE = "Lcom/b/a/c/a;->a"


@pytest.mark.parametrize(
    "written",
    [
        CATALOGUE,
        "com.b.a.c.a->a(android.content.Context, String)",  # the observed live answer
        "com.b.a.c.a->a(android.content.Context,java.lang.String)",
        "Lcom/b/a/c/a;->a(Context, String)",
        "  com.b.a.c.a -> a( android.content.Context , String )  ",
        "com/b/a/c/a->a(android.content.Context,java.lang.String)",
    ],
)
def test_a_real_method_resolves_however_it_is_spelled(written: str) -> None:
    resolved = resolve_signature(written, {CATALOGUE: "SLICE"})
    assert resolved == "SLICE", f"{written!r} should resolve to the catalogue entry"


def test_a_method_we_never_recovered_still_resolves_to_nothing() -> None:
    """The strictness that matters. We do not report on code we did not recover."""
    assert resolve_signature("Lcom/evil/Other;->b()", {CATALOGUE: "SLICE"}) is None
    assert resolve_signature("com.b.a.c.a->somethingElse()", {CATALOGUE: "SLICE"}) is None


def test_a_different_class_with_the_same_method_name_does_not_match() -> None:
    """`a()` is everywhere in obfuscated code; the class must still be respected."""
    assert (
        resolve_signature("com.z.z.z->a(android.content.Context, String)", {CATALOGUE: "S"}) is None
    )


def test_arity_breaks_ties_only_between_real_overloads() -> None:
    """Arity discriminates only when the catalogue itself records it.

    The catalogue normally does not, so arity must not be part of the identity — but
    where two overloads ARE recorded with parameters, the right one must win.
    """
    overloads = {
        "Lcom/b/a/c/a;->a(android.content.Context)": "ONE",
        "Lcom/b/a/c/a;->a(android.content.Context,java.lang.String)": "TWO",
    }
    assert resolve_signature("com.b.a.c.a->a(Context, String)", overloads) == "TWO"
    assert resolve_signature("com.b.a.c.a->a(Context)", overloads) == "ONE"


def test_an_empty_or_junk_signature_resolves_to_nothing() -> None:
    for junk in ("", "   ", "->", "not a signature at all"):
        assert resolve_signature(junk, {CATALOGUE: "SLICE"}) is None


def test_canonical_form_is_stable_and_idempotent() -> None:
    once = canonical_signature(CATALOGUE)
    assert canonical_signature(once) == once
    assert canonical_signature("com.b.a.c.a->a(Context, String)") == once


@pytest.mark.parametrize(
    "written",
    [
        # The full JVM descriptor form, observed live from the same model in the same
        # session as the human-readable form above. No commas, so a comma-split arity
        # count reads two parameters as one and the method fails to match itself.
        "Lcom/b/a/c/a;->a(Landroid/content/Context;Ljava/lang/String;)V",
        "Lcom/b/a/c/a;->a(Landroid/content/Context;Ljava/lang/String;)",
    ],
)
def test_jvm_descriptor_parameters_are_counted(written: str) -> None:
    assert resolve_signature(written, {CATALOGUE: "SLICE"}) == "SLICE"


def test_a_parameterless_catalogue_entry_matches_any_arity() -> None:
    """The real case: the catalogue omits parameters, so it cannot contradict them."""
    one_arg = "Lcom/b/a/c/a;->a(Landroid/content/Context;)V"
    assert resolve_signature(one_arg, {CATALOGUE: "SLICE"}) == "SLICE"


def test_primitive_and_array_descriptors_count() -> None:
    from drishti.m4_genai.agents.code_interpreter import canonical_signature as canon
    from drishti.m4_genai.agents.code_interpreter import signature_arity

    assert canon("La;->m(I[Ljava/lang/String;J)V") == "a->m"
    assert signature_arity("La;->m(I[Ljava/lang/String;J)V") == 3
    assert signature_arity("La;->m()V") == 0
    assert signature_arity("La;->m") is None
