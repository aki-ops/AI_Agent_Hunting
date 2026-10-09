"""Language guard and parent-process rule for the planner, and what happens when a stage loses all its searches."""
from __future__ import annotations

import json
from pathlib import Path

from hunting.plan import render_plan_md, verify
from hunting.plan.build import build_plan
from hunting.plan.language import foreign_words, is_vietnamese_syllable, vocabulary
from hunting.plan.safety import parent_process_problem
from tests.unit.test_intel_plan import GOOD as _GOOD_WITH_A_BAD_SEARCH
from tests.unit.test_intel_plan import ScriptedLlm, _bundle, _results

GOOD = json.loads(json.dumps(_GOOD_WITH_A_BAD_SEARCH))
GOOD["stages"][1]["queries"] = GOOD["stages"][1]["queries"][:1]  # drop the deliberately unsafe 'delete' search

# ----------------------------------------------------------------------------- language


def test_stray_words_of_other_languages_are_flagged_but_vietnamese_english_and_identifiers_are_not():
    prose = (
        "Giả sử kẻ tấn công gửi yêu cầu POST tới tomcatwar.jsp rồi chạy whoami từ tiến trình con của java; nếu đúng thì "
        "có webshell trên máy chủ. Nghiêm trọng: khuyến nghị chuyển giao người săn xem xét, không tự quyết định; thông tin "
        "quyền truy cập thường xuyên. The attackers exploited it, so check running processes."
    )
    assert foreign_words(prose) == []
    mixed = "Quét thăm dò przeciwko máy chủ, tentativa khai thác, ungewöhnliche, explotación thành công."
    assert foreign_words(mixed) == ["przeciwko", "tentativa", "ungewöhnliche", "explotación"]
    # code spans, paths and identifiers are not prose
    assert foreign_words("Thấy `tentativa` và C:\\x\\Zażółć cùng class.module.classLoader.xyzzy") == []


def test_words_that_the_poc_text_itself_uses_are_not_foreign():
    assert foreign_words("Tìm gadgetron trong log") == ["gadgetron"]
    assert foreign_words("Tìm gadgetron trong log", vocabulary("The gadgetron chain is abused")) == []


def test_vietnamese_syllables_are_recognised_with_any_tone_and_other_languages_are_not():
    for word in ("nghiêm", "khuyến", "quyền", "Việt", "thường", "ngoại", "giữ", "trọng", "xuyên"):
        assert is_vietnamese_syllable(word), word
    for word in ("tentativa", "przeciwko", "explotación", "sicherheit", "keamanan"):
        assert not is_vietnamese_syllable(word), word


def test_sixty_stray_words_of_nine_languages_are_caught():
    stray = (
        "segurança ataque servidor conexão arquivo usuário execução explotación conexión archivo ejecución seguridad "
        "angriff sicherheit verbindung ausführung benutzer attaque sécurité connexion exécution fichier utilisateur "
        "bezpieczeństwo połączenie użytkownik wykonanie attacco sicurezza connessione esecuzione serangan keamanan "
        "koneksi pengguna aanval beveiliging verbinding gebruiker saldırı güvenlik bağlantı kullanıcı"
    ).split()
    missed = [w for w in stray if foreign_words(f"Kẻ tấn công {w} vào hệ thống") != [w]]
    assert not missed, missed


# ----------------------------------------------------------------------------- parent-process rule


def test_endpoint_process_searches_must_filter_on_the_parent():
    bare = 'search index={{INDEX_ENDPOINT}} process_name="whoami" | stats count by dest'
    assert "no filter on the parent process" in (parent_process_problem(bare, "endpoint") or "")
    only_listed = 'search index={{INDEX_ENDPOINT}} process_name="whoami" | stats count by dest, parent_process_name'
    assert parent_process_problem(only_listed, "endpoint")  # a mention in the by-clause is not a filter
    for ok in (
        'search index={{INDEX_ENDPOINT}} parent_process_name="java" process_name="sh" | stats count',
        'search index={{INDEX_ENDPOINT}} parent_process_name IN ("java","java.exe") process_name="whoami" | stats count',
        'search index={{INDEX_ENDPOINT}} process_name="sh" | where match(parent_process_name, "(?i)tomcat") | stats count',
        'search index={{INDEX_ENDPOINT}} process_name="sh" | where parent_process="/usr/bin/java" | stats count',
    ):
        assert parent_process_problem(ok, "endpoint") is None, ok
    # file/registry checks and other sources are exempt; a negative filter does not constrain
    assert parent_process_problem('search index={{INDEX_ENDPOINT}} file_name="shell.jsp" | stats count by dest', "endpoint") is None
    assert parent_process_problem('search index={{INDEX_WEB}} uri_path="/x" | stats count', "web") is None
    assert parent_process_problem('search index={{INDEX_ENDPOINT}} process_name="sh" parent_process_name!="cron" | stats count', "endpoint")


# ----------------------------------------------------------------------------- builder


def _with(reply: dict, *, spl: str | None = None, description: str | None = None) -> dict:
    copy = json.loads(json.dumps(reply))
    if spl is not None:
        copy["stages"][2]["queries"][0]["spl"] = spl
    if description is not None:
        copy["stages"][0]["description"] = description
    return copy


BARE = 'search index={{INDEX_ENDPOINT}} process_name="whoami" | stats count by dest, parent_process_name'


def test_builder_asks_for_a_parent_filter_and_a_rewrite_of_stray_words(tmp_path: Path):
    bad = _with(GOOD, spl=BARE, description="Quét przeciwko dịch vụ")
    llm = ScriptedLlm(bad, GOOD)
    plan = build_plan(_bundle(tmp_path), llm, attempts=3)
    assert len(llm.prompts) == 2
    repair = llm.prompts[1][0]
    assert "no filter on the parent process" in repair and "language:" in repair and "przeciwko" in repair
    assert "przeciwko" not in plan.model_dump_json()
    assert 'parent_process_name="widgetd"' in plan.stages[2].queries[0].spl
    # the first prompt states both rules to the model
    first = llm.prompts[0][0]
    assert "parent_process_name" in first and "ONLY Vietnamese and English" in first


def test_wording_problems_get_one_rewrite_not_the_whole_budget_and_the_words_are_listed(tmp_path: Path):
    stubborn = ScriptedLlm(_with(GOOD, description="Quét przeciwko dịch vụ"))
    plan = build_plan(_bundle(tmp_path), stubborn, attempts=3)
    assert len(stubborn.prompts) == 2  # first reply + one rewrite, then the plan is kept
    assert any("possible foreign-language words" in d and "przeciwko" in d for d in plan.dropped)


def test_a_stage_that_lost_every_search_is_flagged_and_never_reads_as_clear(tmp_path: Path):
    plan = build_plan(_bundle(tmp_path), ScriptedLlm(_with(GOOD, spl=BARE)), attempts=1)
    assert plan.stages[2].queries == [] and any("parent process" in d for d in plan.dropped)
    assert "không còn truy vấn hợp lệ" in render_plan_md(plan)
    v, nxt = verify(plan, _results(plan))
    assert v.decision == "RERUN_INCOMPLETE" and nxt is None
    assert v.stages[2].status == "INCOMPLETE" and "không có truy vấn" in " ".join(v.stages[2].notes)
