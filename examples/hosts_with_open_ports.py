import json
import os

from recona import Client


def main() -> None:
    # Init client
    api_token = os.getenv("RECONA_API_TOKEN")
    client = Client(api_token)

    # Prepare search query

    q = "ports.port.not_eq: ''"
    results = client.search_ip(q)

    for r in results.results[:10]:
        print(json.dumps(r, default=lambda o: o.__dict__, sort_keys=True, indent=4))

    if len(results.results) > 10:
        print(f"...and {len(results.results) - 10} more results")


if __name__ == "__main__":
    main()
