from pathlib import Path

from check_dependency_policy import violations


def write_lock(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "Cargo.lock"
    path.write_text(body)
    return path


def test_accepts_crates_io_lock(tmp_path: Path):
    lock = write_lock(tmp_path, '[[package]]\nname="safe"\nversion="1.0.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n')
    assert violations(lock) == []


def test_rejects_incident_packages_and_unknown_sources(tmp_path: Path):
    lock = write_lock(tmp_path, '[[package]]\nname="arrayref"\nversion="0.3.10"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n[[package]]\nname="proc-macro1"\nversion="1.0.107"\n[[package]]\nname="other"\nversion="1.0.0"\nsource="git+https://example.test/repo"\n')
    result = violations(lock)
    assert any("arrayref 0.3.10" in item for item in result)
    assert any("proc-macro1" in item for item in result)
    assert any("unapproved source" in item for item in result)
