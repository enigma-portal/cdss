"""Apply reviewed framework mappings to stored incident guidance."""

from app.database import get_db_connection
from app.database.seed import seed_knowledge_base
from app.services.recommendation_engine import rebuild_recommendations


def main():
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
