from hunting.contracts.transforms import (
    FileTypeSemanticTransform,
    get_transform_by_name,
    get_transform_for_constraint,
    is_literal_telemetry_token,
)


def test_file_type_semantic_transform_is_literal_passthrough() -> None:
    transform = FileTypeSemanticTransform()

    assert not transform.matches_constraint("file_type", "PowerPoint presentation")
    assert not transform.matches_constraint("kind", "PowerPoint")
    assert transform.get_retrieval_terms("file_type", "PowerPoint presentation") == ()
    assert transform.get_retrieval_terms("file_type", "Word document") == ()
    assert transform.get_retrieval_terms("file_type", "PDF document") == ()
    assert transform.get_retrieval_terms("file_extension", ".pdf") == (".pdf",)
    assert transform.get_retrieval_terms("file_name", "secret.pdf") == ("secret.pdf",)
    assert is_literal_telemetry_token(".pdf")
    assert not is_literal_telemetry_token(".pptx.crypt")
    assert not is_literal_telemetry_token("PowerPoint presentation")


def test_file_type_semantic_transform_row_evaluation() -> None:
    transform = FileTypeSemanticTransform()

    row1 = {"TargetFilename": "C:\\Users\\analyst\\Downloads\\Q3_Strategy.pdf"}
    assert transform.evaluates_row(row1, "file_name", "Q3_Strategy.pdf")
    assert not transform.evaluates_row(row1, "file_type", "PowerPoint presentation")

    row2 = {"_raw": "osquery file_events path=/tmp/notes.pdf event=created"}
    assert transform.evaluates_row(row2, "file_extension", ".pdf")

    row3 = {"TargetFilename": "C:\\Windows\\notepad.exe"}
    assert not transform.evaluates_row(row3, "file_extension", ".pdf")


def test_file_type_transform_predicates() -> None:
    transform = FileTypeSemanticTransform()
    assert transform.to_spl_predicate("file_path", "file_type", "PowerPoint presentation") == ""

    spl = transform.to_spl_predicate("file_path", "file_extension", ".pdf")
    assert 'file_path="*.pdf*"' in spl

    sql, params = transform.to_sql_predicate("path", "file_extension", ".pdf")
    assert sql == "(path LIKE ?)"
    assert params == ["%.pdf%"]


def test_get_transform_for_constraint_registry() -> None:
    assert get_transform_for_constraint("file_type", "PowerPoint presentation") is None
    assert isinstance(get_transform_for_constraint("file_extension", ".pdf"), FileTypeSemanticTransform)

    t2 = get_transform_by_name("file_type_expansion")
    assert isinstance(t2, FileTypeSemanticTransform)
