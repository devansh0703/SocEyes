from __future__ import annotations

import argparse
import json
from pathlib import Path

from common import ELASTICSEARCH_URL, elastic_session, wait_for_elasticsearch


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Find candidate rules for a log using Elasticsearch BM25")
    parser.add_argument("--log-message", help="Raw log message to search against the unified rule catalog")
    parser.add_argument("--file", help="Read the log message from a file")
    parser.add_argument("--top-k", type=int, default=10, help="Maximum number of candidate rules")
    return parser.parse_args()


def load_message(args: argparse.Namespace) -> str:
    if args.log_message:
        return args.log_message.strip()
    if args.file:
        return Path(args.file).read_text(encoding="utf-8").strip()
    raise SystemExit("Provide --log-message or --file")


def main() -> int:
    args = parse_args()
    message = load_message(args)
    wait_for_elasticsearch()
    session = elastic_session()

    payload = {
        "size": args.top_k,
        "_source": [
            "rule_id",
            "source",
            "engine",
            "title",
            "description",
            "path",
            "level",
            "type",
            "tags",
        ],
        "query": {
            "multi_match": {
                "query": message,
                "type": "best_fields",
                "fields": [
                    "title^5",
                    "description^4",
                    "query^3",
                    "search_text^6",
                    "tags^2",
                    "product^2",
                    "service^2",
                    "category^2",
                ],
            }
        },
    }

    response = session.get(f"{ELASTICSEARCH_URL}/rule-catalog/_search", json=payload, timeout=60)
    response.raise_for_status()
    hits = response.json().get("hits", {}).get("hits", [])
    print(json.dumps({"query": message, "matches": hits}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
