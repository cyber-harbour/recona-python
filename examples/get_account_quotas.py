import json
import os

from recona import Client


def main() -> None:
    api_token = os.getenv("RECONA_API_TOKEN")

    client = Client(api_token)

    profile = client.get_profile()

    if profile:
        print(
            json.dumps(profile, default=lambda o: o.__dict__, sort_keys=True, indent=4)
        )


if __name__ == "__main__":
    main()
