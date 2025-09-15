import json
import os

from recona import Client


def main() -> None:
    api_token = os.getenv("RECONA_API_TOKEN")

    client = Client(api_token)

    domain = "att.com"
    q = "name.ends_with: " + domain
    results = client.get_all_domains(q)

    for r in results.results[:10]:
        print(json.dumps(r, default=lambda o: o.__dict__, sort_keys=True, indent=4))

    if len(results.results) > 10:
        print(f"...and {len(results.results) - 10} more results")


if __name__ == "__main__":
    main()
