"""Command-line entry point for safe, read-only Wazuh alert ingestion."""

import argparse

from app.database.seed import seed_knowledge_base
from app.environment import load_local_environment
from app.services.incident_processor import process_indexer_alerts


def main():
    parser = argparse.ArgumentParser(description="Fetch Wazuh alerts and create CDSS decisions.")
    parser.add_argument("--size", type=int, default=100, help="Alerts to fetch (1-10000).")
    parser.add_argument("--since", help="Optional ISO-8601 lower timestamp bound.")
    parser.add_argument("--order", choices=("asc", "desc"), default="desc")
    args = parser.parse_args()

    load_local_environment()
    seed_knowledge_base()
    results = process_indexer_alerts(size=args.size, since=args.since, sort_order=args.order)
    created = sum(result.get("created", False) for result in results)
    print(f"Processed {len(results)} Wazuh alerts; created {created} new incidents.")


if __name__ == "__main__":
    main()
