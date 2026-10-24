from pathlib import Path

from phpdetector.detector import is_php_by_content, is_php_by_extension, scan_path


def test_is_php_by_extension():
    assert is_php_by_extension(Path("index.php"))
    assert not is_php_by_extension(Path("index.html"))


def test_is_php_by_content(tmp_path):
    php_file = tmp_path / "snippet.txt"
    php_file.write_text("<?php echo 'hi'; ?>")
    assert is_php_by_content(php_file)

    plain_file = tmp_path / "plain.txt"
    plain_file.write_text("just text")
    assert not is_php_by_content(plain_file)


def test_scan_path(tmp_path):
    (tmp_path / "a.php").write_text("<?php ?>")
    (tmp_path / "b.txt").write_text("nothing here")
    (tmp_path / "c.html").write_text("<?= $x ?>")

    results = scan_path(tmp_path)
    found = {r.path.name for r in results}
    assert found == {"a.php", "c.html"}
