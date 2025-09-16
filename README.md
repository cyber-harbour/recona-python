# Recona Python API Wrapper

[![PyPI version](https://badge.fury.io/py/recona-python.svg)](https://badge.fury.io/py/recona-python)
[![Python Support](https://img.shields.io/pypi/pyversions/recona-python.svg)](https://pypi.org/project/recona-python/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

The official Python wrapper for the [Recona.io](https://recona.io/) API, designed to help developers build robust integrations with Recona's cybersecurity intelligence platform.

[Recona](https://recona.io/) is the most comprehensive Internet assets search engine for cybersecurity professionals, providing real-time intelligence on global internet infrastructure.

## What Recona Provides

Recona delivers extensive cybersecurity intelligence including:

- **Network Intelligence**: 300+ most popular open ports across 3.5 billion publicly accessible IPv4 hosts
- **Technology Stack Detection**: Technologies used on popular ports, IP addresses, and domains
- **Web Hosting Intelligence**: Complete list of websites hosted on each IPv4 address
- **DNS & Domain Intelligence**: Comprehensive DNS and WHOIS records for domain names
- **SSL Certificate Data**: SSL certificates and security information from website hosts
- **Content Analysis**: Structured content analysis of website homepages
- **Threat Intelligence**: Abuse reports and security incidents associated with IPv4 hosts
- **Business Intelligence**: Organization and industry data linked to domain names
- **Contact Discovery**: Email addresses discovered during internet scanning

For detailed information about available data, visit our [Our Data](https://recona.io) page.

## Authentication

Recona API uses **token-based authentication**. API tokens are available exclusively to registered users on their [account page](https://reconatest.io/account).

For comprehensive API documentation, see our [API Reference](https://reconatest.io/docs/search-concept).

## Installation

### Install from PyPI
```bash
pip install recona-python
```

### Upgrade to Latest Version
```bash
pip install --upgrade recona-python
```

### Development Installation
```bash
git clone https://github.com/cyber-harbour/recona-python.git
cd recona-python
pip install -e .
```

## Quick Start

### Basic Usage
```python
import os
from recona import Client
import json

# Initialize client with API token
api_token = os.getenv('RECONA_API_TOKEN')
if not api_token:
    raise ValueError("Please set RECONA_API_TOKEN environment variable")

client = Client(api_token)

try:
    # Get domain details
    result = client.get_domain_details('tesla.com')
    
    if result:
        print("Domain details:")
        print(json.dumps(result, default=str, indent=2, sort_keys=True))
    else:
        print("No data found for domain")
        
except Exception as e:
    print(f"Error retrieving domain details: {e}")
```

### Environment Setup
```bash
# Set your API token as an environment variable
export RECONA_API_TOKEN="your-api-token-here"

# On Windows:
# set RECONA_API_TOKEN=your-api-token-here
```

## Examples

Explore our comprehensive examples:

- [**API Quota Management**](https://github.com/cyber-harbour/recona-python/tree/main/examples/get_account_quotas.py) - Monitor your API usage and limits
- [**Subdomain Discovery**](https://github.com/cyber-harbour/recona-python/tree/main/examples/subdomains_lookup.py) - Advanced search method demonstrations
- [**Domain Intelligence**](https://github.com/cyber-harbour/recona-python/tree/main/examples/domain_lookup.py) - Complete domain analysis workflow

### Running Examples
```bash
# Set your API token
export RECONA_API_TOKEN="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Run an example
python examples/domain_lookup.py
```

## Search Functionality

Recona enables you to search for Internet assets using their digital fingerprints. Construct specific search queries and pass them to `search`, `scroll`, or `count` methods.

### Query Structure
Each search query contains multiple search parameters with the structure:
- **Name**: The field to search
- **Operator**: How to match (equals, contains, starts_with, etc.)
- **Value**: The value to match against

### Search Examples

#### Find Subdomains
```python
import json
import os
from recona import Client

# Initialize client
client = Client(os.getenv('RECONA_API_TOKEN'))

# Search for subdomains of att.com
query = "name.ends_with: .att.com"

try:
    search_results = client.search_domains(query)
    
    # Display first 10 results
    results_to_show = search_results.results[:10]
    
    for result in results_to_show:
        print(json.dumps(result, default=str, indent=2, sort_keys=True))
    
    # Show total count
    total_results = len(search_results.results)
    if total_results > 10:
        print(f"\n...and {total_results - 10} more results")
    
    print(f"\nTotal results found: {total_results}")
    
except Exception as e:
    print(f"Search failed: {e}")
```

#### Advanced Search with Multiple Criteria
```python
from recona import Client
import os

client = Client(os.getenv('RECONA_API_TOKEN'))

# Complex query combining multiple criteria
from recona import Client, ReconaError
import json

if __name__ == '__main__':
    client = Client(os.getenv('RECONA_API_TOKEN'))

    query = 'extract.status_code.not_eq: \'\' AND geo.country_iso_code.eq: RU and technologies.name.eq: Nginx'

    try:
        results = client.search_domains(query)
        print(f"Found {len(results.results)} domains matching criteria")

        for domain in results.results[:5]:  # Show first 5
            print(json.dumps(domain, default=lambda o: o.__dict__, sort_keys=True, indent=4))

    except Exception as e:
        print(f"Advanced search failed: {e}")
```

### Query Building Resources
- **API Documentation**: [Domain Search API](https://recona.io/docs/api)
- **Interactive Query Builder for domains search**: [Domain Filters GUI](https://recona.io/docs/domain-filters)
- **Interactive Query Builder for hosts search**: [Host Filters GUI](https://recona.io/docs/ip-filters)
- **Interactive Query Builder for certificates search**: [Certificate Filters GUI](https://recona.io/docs/certificate-filters)
- **Interactive Query Builder for cve search**: [CVE Filters GUI](https://recona.io/docs/cve-filters)

## Error Handling

### Best Practices
```python
from recona import Client, ReconaError
import json
import os

if __name__ == '__main__':
    client = Client(os.getenv('RECONA_API_TOKEN'))

    try:
        result = client.get_domain_details('example.com')

        if result:
            print(
                json.dumps(result, default=lambda o: o.__dict__, sort_keys=True, indent=4)
            )

    except ReconaError as e:
        print(f"API Error: {e}")
        print(f"Status Code: {e.message}")

    except ValueError as e:
        print(f"Invalid input: {e}")

    except Exception as e:
        print(f"Unexpected error: {e}")
```

### Rate Limiting
```python
import time
import os
from recona import Client, ReconaError

client = Client(os.getenv('RECONA_API_TOKEN'))

def search_with_retry(query, max_retries=3, delay=1):
    """Search with exponential backoff retry logic."""
    for attempt in range(max_retries):
        try:
            return client.search_domains(query)
        except ReconaError as e:
            if e.status_code == 429:  # Rate limited
                wait_time = delay * (2 ** attempt)
                print(f"Rate limited. Waiting {wait_time}s before retry...")
                time.sleep(wait_time)
            else:
                raise
    
    raise Exception(f"Failed after {max_retries} retries")
```

## Development

### Setting Up Development Environment
```bash
# Clone the repository
git clone https://github.com/cyber-harbour/recona-python.git
cd recona-python

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks (optional)
pre-commit install
```

### Running Tests
```bash
# Set test environment variables
export RECONA_API_TOKEN="your-test-token"

# Run tests
python -m pytest tests/ -v

# Run tests with coverage
python -m pytest tests/ --cov=recona --cov-report=html
```

### Code Quality
```bash
# Format code
black recona/
isort recona/

# Lint code
flake8 recona/
mypy recona/

# Security scan
bandit -r recona/
```

## Requirements

- **Python**: 3.8 or higher
- **Dependencies**: See `requirements.txt`
- **Optional**: See `requirements-dev.txt` for development dependencies

## API Reference

For detailed API documentation, visit:
- [**API Reference**](https://recona.io/docs/api)
- [**Search Query Documentation**](https://recona.io/docs/search-concept)
- [**Interactive Query Builder**](https://recona.io/docs/ip-filters)

## License

Distributed under the MIT License. See [LICENSE](https://github.com/cyber-harbour/recona-python/tree/main/LICENSE.md) for more information.

## Support and Community

### Getting Help
- **Documentation**: [Official API Docs](https://recona.io/docs/api)
- **Issues**: [GitHub Issues](https://github.com/cyber-harbour/recona-python/issues)
- **Email Support**: [Contact Recona Support](mailto:info@recona.io)


### Reporting Security Issues
For security-related issues, please email info@recona.io directly instead of using GitHub issues.

---

**Made with ❤️ by the Recona team**