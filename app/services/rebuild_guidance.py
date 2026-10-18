"""Explicit maintenance of legacy guidance, not current contextual recommendations."""

import argparse

from app.database import get_db_connection
from app.database.seed import seed_knowledge_base
from app.services.recommendation_engine import rebuild_recommendations


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--confirm-legacy-rewrite', action='store_true')
    if not parser.parse_args(argv).confirm_legacy_rewrite:
        parser.error('Legacy guidance rewrite requires --confirm-legacy-rewrite; use the investigation workflow for current recommendations.')
    seed_knowledge_base()
    connection = get_db_connection()
    try:
        with connection:
            refreshed = rebuild_recommendations(connection)
        total = connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        covered = connection.execute(
            "SELECT COUNT(DISTINCT incident_id) FROM incident_recommendations"
        ).fetchone()[0]
        mapped = connection.execute("""
            SELECT COUNT(DISTINCT incident_id) FROM incident_recommendations
            WHERE framework LIKE 'MITRE D3FEND%'
        """).fetchone()[0]
        print(f"Refreshed {refreshed} incidents; coverage {covered}/{total}; D3FEND mapped {mapped}.")
    finally:
        connection.close()


if __name__ == "__main__":
    main()
