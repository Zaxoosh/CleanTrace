import json
import zipfile
from pathlib import Path

from cleantrace.takeout import analyse_google_takeout


def test_analyse_google_takeout_detects_location_and_photo_metadata(tmp_path: Path) -> None:
    archive_path = tmp_path / "takeout.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("Takeout/Location History/Records.json", "{}")
        archive.writestr(
            "Takeout/Google Photos/photo.jpg.json",
            json.dumps({"geoData": {"latitude": 51.5, "longitude": -0.1}}),
        )
        archive.writestr("Takeout/Drive/shared.txt", "Anyone with the link can view")

    summary = analyse_google_takeout(archive_path, profile_id=1)

    titles = {finding.title for finding in summary.findings}
    assert "Google Takeout contains location history files" in titles
    assert "Google Photos metadata may contain location clues" in titles
    assert "Google Takeout includes shared-link metadata" in titles
    assert summary.files_seen == 3
