from dataclasses import dataclass, field
from typing import List, Optional

from dataclasses_json import dataclass_json


@dataclass_json
@dataclass
class ProductsPermission:
    recona: bool = False


@dataclass_json
@dataclass
class Permissions:
    ui_rows_limit: int = 0
    api_rows_limit: int = 0
    request_limit_per_day: int = 0
    filter_limits: int = 0
    request_rate_limit: int = 0


@dataclass_json
@dataclass
class CustomerResponse:
    id: int
    login: str
    status: int
    nickname: str
    subscription_id: int
    subscription_name: Optional[str] = None
    group_id: int = 0
    group_title: Optional[str] = None
    role_id: int = 0
    subscription_started_at: Optional[str] = None
    subscription_expires_at: Optional[str] = None
    organization_id: int = 0
    organization_title: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    last_seen: Optional[str] = None
    total_request_count: int = 0
    daily_request_count: int = 0
    week_request_count: int = 0
    request_limit_per_day: int = 0
    enabled_two_fa: bool = False
    products_permission: Optional[ProductsPermission] = None


@dataclass_json
@dataclass
class Profile(CustomerResponse):
    permissions: Optional[Permissions] = field(default_factory=Permissions)
    request_count: int = 0
    request_limit_per_day: int = 0
    start_at: Optional[str] = None
    EndAt: Optional[str] = None


@dataclass_json
@dataclass
class EPSS:
    score: float
    percentile: float
    date: str


@dataclass_json
@dataclass
class DomainCVE:
    base_score: Optional[float] = None
    id: Optional[str] = None
    severity: Optional[str] = None
    vector: Optional[str] = None
    description: Optional[str] = None
    technologies: Optional[List[str]] = None
    epss: Optional[EPSS] = None
    has_poc: bool = False


@dataclass_json
@dataclass
class ExposedPhp:
    path: Optional[str] = None


@dataclass_json
@dataclass
class StringsKeyValue:
    key: Optional[str] = None
    value: Optional[str] = None


@dataclass_json
@dataclass
class ExposedEnv:
    path: Optional[str] = None
    data: Optional[List[StringsKeyValue]] = None
    raw: Optional[str] = None


@dataclass_json
@dataclass
class ExposedGit:
    path: Optional[str] = None
    raw: Optional[str] = None


@dataclass_json
@dataclass
class SData:
    env: Optional[List[ExposedEnv]] = None
    git: Optional[List[ExposedGit]] = None
    php_files: Optional[List[ExposedPhp]] = None


@dataclass_json
@dataclass
class DomainGeoLocation:
    lon: Optional[float] = None
    lat: Optional[float] = None


@dataclass_json
@dataclass
class DomainGeoInfo:
    city_name: Optional[str] = None
    country: Optional[str] = None
    country_iso_code: Optional[str] = None
    location: Optional[DomainGeoLocation] = None
    ip: Optional[str] = None


@dataclass_json
@dataclass
class DomainIspInfo:
    as_num: Optional[int] = None
    as_org: Optional[str] = None
    as_name: Optional[str] = None
    ip: Optional[str] = None
    network: Optional[str] = None


@dataclass_json
@dataclass
class BugBounty:
    name: Optional[str] = None
    program_url: Optional[str] = None
    count: Optional[int] = None
    change: Optional[int] = None
    is_new: bool = False
    platform: Optional[str] = None
    bounty: bool = False
    last_updated: Optional[str] = None


@dataclass_json
@dataclass
class Screenshot:
    is_screenshotted: bool = False
    screenshot_time: Optional[str] = None
    screenshot_error: Optional[str] = None


@dataclass_json
@dataclass
class DomainCveList:
    base_score: Optional[float] = None
    id: Optional[str] = None
    severity: Optional[str] = None
    vector: Optional[str] = None
    technology: Optional[str] = None


@dataclass_json
@dataclass
class CveLists:
    http_cve_list: Optional[List[DomainCveList]] = None


@dataclass_json
@dataclass
class Env:
    text: Optional[str] = None
    path: Optional[str] = None


@dataclass_json
@dataclass
class Files:
    env: Optional[Env] = None


@dataclass_json
@dataclass
class Registrar:
    created_date: Optional[str] = None
    domain_dnssec: Optional[str] = None
    domain_id: Optional[str] = None
    domain_name: Optional[str] = None
    domain_status: Optional[str] = None
    expiration_date: Optional[str] = None
    name_servers: Optional[str] = None
    referral_url: Optional[str] = None
    registrar_id: Optional[str] = None
    registrar_name: Optional[str] = None
    updated_date: Optional[str] = None
    whois_server: Optional[str] = None
    emails: Optional[str] = None


@dataclass_json
@dataclass
class Registrant:
    id: Optional[str] = None
    name: Optional[str] = None
    organization: Optional[str] = None
    street: Optional[str] = None
    street_ext: Optional[str] = None
    city: Optional[str] = None
    province: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = None
    phone: Optional[str] = None
    phone_ext: Optional[str] = None
    fax: Optional[str] = None
    fax_ext: Optional[str] = None
    email: Optional[str] = None


@dataclass_json
@dataclass
class WhoisParsed:
    error_code: Optional[int] = None
    registrar: Optional[Registrar] = None
    registrant: Optional[Registrant] = None
    admin: Optional[Registrant] = None
    tech: Optional[Registrant] = None
    bill: Optional[Registrant] = None
    updated_at: Optional[str] = None


@dataclass_json
@dataclass
class SpfModifier:
    name: Optional[str] = None
    value: Optional[str] = None


@dataclass_json
@dataclass
class SpfMechanism:
    name: Optional[str] = None
    qualifier: Optional[str] = None
    value: Optional[str] = None


@dataclass_json
@dataclass
class SpfValidationError:
    description: Optional[str] = None
    target: Optional[str] = None


@dataclass_json
@dataclass
class SPF:
    version: Optional[str] = None
    validation_errors: Optional[List[SpfValidationError]] = None
    mechanisms: Optional[List[SpfMechanism]] = None
    modifiers: Optional[List[SpfModifier]] = None
    raw: Optional[str] = None


@dataclass_json
@dataclass
class SOARecord:
    ns: Optional[str] = None
    email: Optional[str] = None
    serial: Optional[int] = None
    refresh: Optional[int] = None
    retry: Optional[int] = None
    expire: Optional[int] = None
    min_ttl: Optional[int] = None


@dataclass_json
@dataclass
class DNSRecords:
    A: Optional[List[str]] = None
    AAAA: Optional[List[str]] = None
    CNAME: Optional[List[str]] = None
    TXT: Optional[List[str]] = None
    NS: Optional[List[str]] = None
    MX: Optional[List[str]] = None
    SPF: Optional[List[SPF]] = None
    SOA: Optional[SOARecord] = None
    CAA: Optional[List[str]] = None
    updated_at: Optional[str] = None


@dataclass_json
@dataclass
class DomainCertificateIssuerDN:
    common_name: Optional[str] = None
    organization: Optional[str] = None
    country: Optional[str] = None


@dataclass_json
@dataclass
class DomainCertificateSubjectDN:
    common_name: Optional[str] = None
    organization: Optional[str] = None
    country: Optional[str] = None


@dataclass_json
@dataclass
class CertSummary:
    fingerprint_sha256: Optional[str] = None
    issuer_dn: Optional[DomainCertificateIssuerDN] = None
    subject_dn: Optional[DomainCertificateSubjectDN] = None
    tls_version: Optional[str] = None
    validity_end: Optional[str] = None
    dns_names: Optional[List[str]] = None
    updated_at: Optional[str] = None


@dataclass_json
@dataclass
class RequestAnswer:
    ip: Optional[str] = None
    host: Optional[str] = None
    raw_response: Optional[str] = None
    raw_response_bytes: Optional[bytes] = None
    headers: Optional[List[str]] = None
    status_code: Optional[int] = None
    error: Optional[str] = None
    external_redirect_url: Optional[str] = None
    proxy_url: Optional[str] = None
    proxy_port: Optional[int] = None
    proxy_type: Optional[str] = None


@dataclass_json
@dataclass
class Domain:
    # Basic domain identification
    name: Optional[str] = None  # The primary domain name (e.g., "example.com")
    name_reversed: Optional[str] = None  # Domain name in reverse order for indexing

    # WHOIS information and metadata
    whois_parsed: Optional["WhoisParsed"] = None  # Structured WHOIS data
    whois_error: Optional[str] = None  # Error message if WHOIS lookup failed
    whois_updated_at: Optional[str] = None  # Timestamp of last WHOIS update
    updated_at: Optional[str] = None  # Last update timestamp for this record
    whois: Optional[str] = None  # Raw WHOIS response data

    # DNS and network configuration
    dns_records: Optional["DNSRecords"] = None  # Complete DNS record information

    # Web content and analysis
    extract: Optional["Extract"] = None  # Extracted content from domain's website
    screenshot: Optional["Screenshot"] = None  # Screenshot of the domain's main page

    # SSL/TLS certificate information
    certificate_summaries: Optional["CertSummary"] = None  # SSL certificate details

    # DNS record type flags
    is_ns: Optional[bool] = None  # Has Name Server records
    is_mx: Optional[bool] = None  # Has Mail Exchange records
    is_ptr: Optional[bool] = None  # Has Pointer records (reverse DNS)
    is_cname: Optional[bool] = None  # Has Canonical Name records
    is_subdomain: Optional[bool] = None  # This is a subdomain, not a root domain

    # Domain structure and parsing
    suffix: Optional[str] = None  # Top-level domain (TLD)
    name_full_reverse: Optional[str] = None  # Complete reversed domain name
    name_without_tld: Optional[str] = None  # Domain name excluding the TLD
    subdomain_part: Optional[str] = None  # The subdomain portion only

    # HTTP request/response data
    request_answer: Optional["RequestAnswer"] = None  # HTTP response information

    # Technology detection and analysis
    technologies: Optional[List["Technology"]] = (
        None  # Detected web technologies, frameworks, etc.
    )

    # Geographic and ISP information
    geo: Optional[List["DomainGeoInfo"]] = (
        None  # Geographic location data for domain's IPs
    )
    isp: Optional[List["DomainIspInfo"]] = None  # Internet Service Provider information

    # Security and vulnerability data
    severity_details: Optional["SeverityDetails"] = None  # Security severity assessment
    cve_list: Optional[List["DomainCVE"]] = None  # Common Vulnerabilities and Exposures

    # Processing and operational flags
    is_force_import: Optional[bool] = None  # Force reimport of domain data
    is_domain_extended: Optional[bool] = None  # Extended domain analysis performed
    user_scan_at: Optional[str] = None  # Timestamp of user-initiated scan
    operation_type: Optional[str] = None  # Type of operation performed on domain


@dataclass_json
@dataclass
class TotalItems:
    value: Optional[int] = None
    relation: Optional[str] = None


@dataclass_json
@dataclass
class DomainsResponse:
    total_items: TotalItems
    limit: Optional[int] = None
    offset: Optional[int] = None
    domains: Optional[List[Domain]] = None  # Use your existing Domain class


@dataclass_json
@dataclass
class Location:
    lon: Optional[float] = None
    lat: Optional[float] = None


@dataclass_json
@dataclass
class Geo:
    city_name: Optional[str] = None
    country: Optional[str] = None
    country_iso_code: Optional[str] = None
    location: Optional[Location] = None


@dataclass_json
@dataclass
class ISP:
    as_num: Optional[int] = None
    as_org: Optional[str] = None
    isp: Optional[str] = None
    network: Optional[str] = None


@dataclass_json
@dataclass
class URI:
    full_uri: Optional[str] = None
    host: Optional[str] = None
    path: Optional[str] = None


@dataclass_json
@dataclass
class LinkAttributes:
    no_follow: Optional[bool] = None
    uri: Optional[URI] = None


@dataclass_json
@dataclass
class Link:
    anchor: Optional[str] = None
    attributes: Optional[LinkAttributes] = None


@dataclass_json
@dataclass
class MetaTag:
    name: Optional[str] = None
    value: Optional[str] = None


@dataclass_json
@dataclass
class HTTPHeader:
    name: Optional[str] = None
    value: Optional[str] = None


@dataclass_json
@dataclass
class ResponseChainLink:
    status_code: Optional[int] = None
    headers: Optional[List[HTTPHeader]] = None


@dataclass_json
@dataclass
class Cookies:
    key: Optional[str] = None
    value: Optional[str] = None
    expire: Optional[str] = None
    max_age: Optional[int] = None
    path: Optional[str] = None
    http_only: Optional[bool] = None
    security: Optional[bool] = None


@dataclass_json
@dataclass
class Extract:
    links: Optional[List[Link]] = None
    emails: Optional[List[str]] = None
    errors: Optional[List[str]] = None
    favicon_uri: Optional[URI] = None
    favicon_sha256: Optional[str] = None
    meta_tags: Optional[List[MetaTag]] = None
    description: Optional[str] = None
    response_chain: Optional[List[ResponseChainLink]] = None
    status_code: Optional[int] = None
    headers: Optional[List[HTTPHeader]] = None
    robots_txt: Optional[str] = None
    scripts: Optional[List[str]] = None
    styles: Optional[List[str]] = None
    title: Optional[str] = None
    raw_response: Optional[str] = None
    external_redirect_uri: Optional[URI] = None
    extracted_at: Optional[str] = None
    cookies: Optional[List[Cookies]] = None
    adsense_id: Optional[str] = None
    robots_disallow: Optional[List[str]] = None
    google_analytics_key: Optional[str] = None
    google_site_verification: Optional[str] = None
    google_play_app: Optional[str] = None
    apple_itunes_app: Optional[str] = None


@dataclass_json
@dataclass
class Port:
    banner: Optional[str] = None
    cpe_application: Optional[str] = None
    cpe_hardware: Optional[str] = None
    cpe_os: Optional[str] = None
    device_type: Optional[str] = None
    extract: Optional[Extract] = None
    hostname: Optional[str] = None
    info: Optional[str] = None
    masscan_service_name: Optional[str] = None
    operation_system: Optional[str] = None
    port: Optional[int] = None
    product: Optional[str] = None
    service: Optional[str] = None
    version: Optional[str] = None
    updated_at: Optional[str] = None
    is_ssl: Optional[bool] = None


@dataclass_json
@dataclass
class Technology:
    name: Optional[str] = None
    version: Optional[str] = None
    version_representation: Optional[int] = None
    port: Optional[int] = None
    logo_base64: Optional[str] = None


@dataclass_json
@dataclass
class SeverityDetails:
    high: Optional[int] = None
    low: Optional[int] = None
    medium: Optional[int] = None


@dataclass_json
@dataclass
class AbuseCategory:
    id: Optional[int] = None
    name: Optional[str] = None
    description: Optional[str] = None


@dataclass_json
@dataclass
class AbuseReport:
    reported_at: Optional[str] = None
    comment: Optional[str] = None
    categories: Optional[List[AbuseCategory]] = None


@dataclass_json
@dataclass
class Abuse:
    score: Optional[int] = None
    reports_num: Optional[int] = None
    reports: Optional[List[AbuseReport]] = None
    all_categories: Optional[List[AbuseCategory]] = None
    is_whitelist_weak: Optional[bool] = None
    is_whitelist_strong: Optional[bool] = None
    updated_at: Optional[str] = None


@dataclass_json
@dataclass
class PTRRecord:
    value: Optional[str] = None
    updated_at: Optional[str] = None


@dataclass_json
@dataclass
class CVE:
    base_score: Optional[float] = None
    id: Optional[str] = None
    ports: Optional[List[int]] = None
    severity: Optional[str] = None
    vector: Optional[str] = None
    description: Optional[str] = None
    technologies: Optional[List[str]] = None
    epss: Optional[EPSS] = None
    has_poc: Optional[bool] = None


@dataclass_json
@dataclass
class CertificateSummary:
    fingerprint_sha256: Optional[str] = None
    issuer_dn: Optional[DomainCertificateIssuerDN] = None
    subject_dn: Optional[DomainCertificateSubjectDN] = None
    tls_version: Optional[str] = None
    validity_end: Optional[str] = None
    dns_names: Optional[List[str]] = None
    port: Optional[int] = None
    updated_at: Optional[str] = None


@dataclass_json
@dataclass
class Host:
    ip: Optional[str] = None
    geo: Optional[Geo] = None
    isp: Optional[ISP] = None
    ports: Optional[List[Port]] = None
    ptr_record: Optional[PTRRecord] = None
    severity_details: Optional[SeverityDetails] = None
    cve_list: Optional[List[CVE]] = None
    technologies: Optional[List[Technology]] = None
    abuses: Optional[Abuse] = None
    certificate_summaries: Optional[List[CertificateSummary]] = None
    updated_at: Optional[str] = None


@dataclass_json
@dataclass
class Reference:
    source: str
    tags: Optional[List[str]] = None
    url: str = ""


@dataclass_json
@dataclass
class KEV:
    vulnerability_name: str
    action_required: str
    exploit_added: Optional[str] = None
    action_due: Optional[str] = None


@dataclass_json
@dataclass
class CPEMatch:
    criteria: str
    match_criteria_id: str
    version_end_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    version_start_excluding: Optional[str] = None
    version_start_including: Optional[str] = None
    vulnerable: bool = False


@dataclass_json
@dataclass
class Node:
    cpe_match: Optional[List[CPEMatch]] = None
    negate: bool = False
    operator: str = ""


@dataclass_json
@dataclass
class Configuration:
    nodes: Optional[List[Node]] = None
    operator: str = ""


@dataclass_json
@dataclass
class CVSSDataV2:
    access_complexity: str
    access_vector: str
    authentication: str
    availability_impact: str
    base_score: float
    confidentiality_impact: str
    integrity_impact: str
    vector_string: str
    version: str


@dataclass_json
@dataclass
class CVSSV2:
    ac_insuf_info: bool
    base_severity: str
    cvss_data: Optional[CVSSDataV2] = None
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    obtain_all_privilege: bool = False
    obtain_other_privilege: bool = False
    obtain_user_privilege: bool = False
    source: str = ""
    type: str = ""
    user_interaction_required: bool = False


@dataclass_json
@dataclass
class CVSSDataV3:
    attack_complexity: str
    attack_vector: str
    availability_impact: str
    base_score: float
    base_severity: str
    confidentiality_impact: str
    integrity_impact: str
    privileges_required: str
    scope: str
    user_interaction: str
    vector_string: str
    version: str


@dataclass_json
@dataclass
class CVSSV3:
    cvss_data: Optional[CVSSDataV3] = None
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    source: str = ""
    type: str = ""


@dataclass_json
@dataclass
class CVSSDataV4:
    attack_complexity: str
    attack_requirements: str
    attack_vector: str
    automatable: str
    availability_requirements: str
    base_score: float
    base_severity: str
    confidentiality_requirements: str
    exploit_maturity: str
    integrity_requirements: str
    modified_attack_complexity: str
    modified_attack_requirements: str
    modified_attack_vector: str
    modified_privileges_required: str
    modified_subsequent_system_availability: str
    modified_subsequent_system_confidentiality: str
    modified_subsequent_system_integrity: str
    modified_user_interaction: str
    modified_vulnerable_system_availability: str
    modified_vulnerable_system_confidentiality: str
    modified_vulnerable_system_integrity: str
    privileges_required: str
    provider_urgency: str
    recovery: str
    safety: str
    subsequent_system_availability: str
    subsequent_system_confidentiality: str
    subsequent_system_integrity: str
    user_interaction: str
    value_density: str
    vector_string: str
    version: str
    vulnerability_response_effort: str
    vulnerable_system_availability: str
    vulnerable_system_confidentiality: str
    vulnerable_system_integrity: str


@dataclass_json
@dataclass
class CVSSV4:
    cvss_data: Optional[CVSSDataV4] = None
    source: str = ""
    type: str = ""


@dataclass_json
@dataclass
class Metric:
    v2: Optional[List[CVSSV2]] = None
    v3: Optional[List[CVSSV3]] = None
    v3_1: Optional[List[CVSSV3]] = None
    v4: Optional[List[CVSSV4]] = None


@dataclass_json
@dataclass
class CVSS:
    score: float
    severity: str
    metrics: Optional[Metric] = None


@dataclass_json
@dataclass
class POC:
    references: Optional[List[str]] = None


@dataclass_json
@dataclass
class CWE:
    code: str
    name: str
    abstraction: str
    structure: str
    status: str
    description: str
    extended_description: str


@dataclass_json
@dataclass
class NistCVEData:
    id: str
    status: str
    has_poc: bool
    has_epss: bool
    has_cvss: bool
    has_targets: bool
    is_kev_listed: bool
    tags: Optional[List[str]] = None
    description: str = ""
    references: Optional[List[Reference]] = None
    kev: Optional[KEV] = None
    cvss: Optional[CVSS] = None
    epss: Optional[EPSS] = None
    poc: Optional[POC] = None
    cwes: Optional[List[str]] = None
    configurations: Optional[List[Configuration]] = None
    last_modified_at: Optional[str] = None
    published_at: Optional[str] = None


@dataclass_json
@dataclass
class CVEResponse:
    cve_list: Optional[List[NistCVEData]] = None


@dataclass_json
@dataclass
class CWEParams:
    ids: Optional[List[str]] = None


@dataclass_json
@dataclass
class CWEResponse:
    items: Optional[List[CWE]] = None


@dataclass_json
@dataclass
class Pagination:
    limit: Optional[int] = None
    offset: Optional[int] = None


@dataclass_json
@dataclass
class PaginationResponse:
    total_items: TotalItems
    pagination: Pagination


@dataclass_json
@dataclass
class Search:
    query: Optional[str] = None
    filters: Optional[str] = None


@dataclass_json
@dataclass
class SearchRequest:
    search: Search
    pagination: Pagination


@dataclass_json
@dataclass
class Validation:
    valid: Optional[bool] = None
    reason: Optional[str] = None


@dataclass_json
@dataclass
class AuthorityInfoAccess:
    issuer_urls: Optional[List[str]] = None
    ocspurls: Optional[List[str]] = None


@dataclass_json
@dataclass
class BasicConstraints:
    is_ca: Optional[bool] = None


@dataclass_json
@dataclass
class CertPoliciesUserNotice:
    explicit_text: Optional[str] = None


@dataclass_json
@dataclass
class CertPolicies:
    cps: Optional[List[str]] = None
    id: Optional[str] = None
    user_notice: Optional[List[CertPoliciesUserNotice]] = None


@dataclass_json
@dataclass
class ExtendedKeyUsage:
    client_auth: Optional[bool] = None
    server_auth: Optional[bool] = None


@dataclass_json
@dataclass
class KeyUsage:
    content_commitment: Optional[bool] = None
    digital_signature: Optional[bool] = None
    key_encipherment: Optional[bool] = None
    value: Optional[int] = None


@dataclass_json
@dataclass
class SubjectAltName:
    dns_names: Optional[List[str]] = None
    dns_names_v2: Optional[List[str]] = None
    ip_addresses: Optional[List[str]] = None


@dataclass_json
@dataclass
class Extensions:
    authority_info_access: Optional[AuthorityInfoAccess] = None
    authority_key_id: Optional[str] = None
    basic_constraints: Optional[BasicConstraints] = None
    certificate_policies: Optional[List[CertPolicies]] = None
    crl_distribution_points: Optional[List[str]] = None
    extended_key_usage: Optional[ExtendedKeyUsage] = None
    key_usage: Optional[KeyUsage] = None
    signed_certificate_timestamps: Optional[List["SignedCertificateTimestamps"]] = None
    subject_alt_name: Optional[SubjectAltName] = None
    subject_key_id: Optional[str] = None


@dataclass_json
@dataclass
class Issuer:
    common_name: Optional[List[str]] = None
    country: Optional[List[str]] = None
    email_address: Optional[List[str]] = None
    locality: Optional[List[str]] = None
    organization: Optional[List[str]] = None
    organizational_unit: Optional[List[str]] = None
    province: Optional[List[str]] = None


@dataclass_json
@dataclass
class SignatureAlgorithm:
    name: Optional[str] = None
    oid: Optional[str] = None


@dataclass_json
@dataclass
class Signature:
    self_signed: Optional[bool] = None
    signature_algorithm: Optional[SignatureAlgorithm] = None
    valid: Optional[bool] = None
    value: Optional[str] = None


@dataclass_json
@dataclass
class Subject:
    common_name: Optional[List[str]] = None
    common_name_lowercase: Optional[List[str]] = None
    country: Optional[List[str]] = None
    email_address: Optional[List[str]] = None
    jurisdiction_country: Optional[List[str]] = None
    jurisdiction_locality: Optional[List[str]] = None
    jurisdiction_province: Optional[List[str]] = None
    locality: Optional[List[str]] = None
    organization: Optional[List[str]] = None
    organizational_unit: Optional[List[str]] = None
    postal_code: Optional[List[str]] = None
    province: Optional[List[str]] = None
    serial_number: Optional[List[str]] = None
    street_address: Optional[List[str]] = None


@dataclass_json
@dataclass
class EcdsaPublicKey:
    b: Optional[str] = None
    curve: Optional[str] = None
    gx: Optional[str] = None
    gy: Optional[str] = None
    length: Optional[int] = None
    n: Optional[str] = None
    p: Optional[str] = None
    pub: Optional[str] = None
    x: Optional[str] = None
    y: Optional[str] = None


@dataclass_json
@dataclass
class KeyAlgorithm:
    name: Optional[str] = None


@dataclass_json
@dataclass
class RSAPublicKey:
    exponent: Optional[int] = None
    length: Optional[int] = None
    modulus: Optional[str] = None


@dataclass_json
@dataclass
class SubjectKeyInfo:
    ecdsa_public_key: Optional[EcdsaPublicKey] = None
    fingerprint_sha256: Optional[str] = None
    key_algorithm: Optional[KeyAlgorithm] = None
    rsapublic_key: Optional[RSAPublicKey] = None


@dataclass_json
@dataclass
class Validity:
    end: Optional[str] = None
    length: Optional[int] = None
    start: Optional[str] = None


@dataclass_json
@dataclass
class Parsed:
    extensions: Optional[Extensions] = None
    fingerprint_md5: Optional[str] = None
    fingerprint_sha1: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    issuer: Optional[Issuer] = None
    issuer_dn: Optional[str] = None
    names: Optional[List[str]] = None
    redacted: Optional[bool] = None
    serial_number: Optional[str] = None
    signature: Optional[Signature] = None
    signature_algorithm: Optional[SignatureAlgorithm] = None
    spki_subject_fingerprint: Optional[str] = None
    subject: Optional[Subject] = None
    subject_dn: Optional[str] = None
    subject_key_info: Optional[SubjectKeyInfo] = None
    tbs_fingerprint: Optional[str] = None
    tbs_noct_fingerprint: Optional[str] = None
    validation_level: Optional[str] = None
    validity: Optional[Validity] = None
    version: Optional[int] = None


@dataclass_json
@dataclass
class SignedCertificateTimestamps:
    log_id: Optional[str] = None
    signature: Optional[str] = None
    timestamp: Optional[int] = None
    version: Optional[int] = None


@dataclass_json
@dataclass
class Certificate:
    parsed: Optional[Parsed] = None
    raw: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    validation: Optional[Validation] = None
    updated_at: Optional[str] = None


@dataclass_json
@dataclass
class ASSubnet:
    cidr: Optional[str] = None
    isp: Optional[str] = None


@dataclass_json
@dataclass
class AS:
    number: Optional[int] = None
    organization: Optional[str] = None
    ipv4_ranges: Optional[List[ASSubnet]] = None
    ipv6_ranges: Optional[List[ASSubnet]] = None
    updated_at: Optional[str] = None
