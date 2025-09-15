import json
import os

from recona import Client


def main() -> None:
    api_token = os.getenv("RECONA_API_TOKEN")

    if not api_token:
        print("Error: RECONA_API_TOKEN environment variable is not set.")
        return

    client = Client(api_token)

    host = "1.1.1.1"
    details = client.get_ip_details(host)
    if details:
        print(
            json.dumps(details, default=lambda o: o.__dict__, sort_keys=True, indent=4)
        )
    else:
        print("Data not available for this host.")
        return


if __name__ == "__main__":
    main()
