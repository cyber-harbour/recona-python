import json
import os

from recona import Client


def main() -> None:
    # Init client
    api_token = os.getenv("RECONA_API_TOKEN")

    client = Client(api_token)

    # Prepare search query
    fingerprint = "0000029696ac9c3874167723f63a5831db9b6be54528836e2bc28da5310b1ab0"
    result = client.get_certificate_details(fingerprint)

    if result:
        print(
            json.dumps(result, default=lambda o: o.__dict__, sort_keys=True, indent=4)
        )


if __name__ == "__main__":
    main()
