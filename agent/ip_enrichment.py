"""
IP Intelligence Enrichment
Uses ipwhois to enrich source IPs with geolocation and ASN information.
"""

import ipaddress
from functools import lru_cache


class IPEnrichment:
    """Enriches IP addresses with geolocation, ASN, and organization data."""

    def __init__(self):
        self._cache = {}

    def enrich_ip(self, ip: str) -> dict:
        """
        Look up geolocation and ASN information for an IP address.
        
        Returns:
            {
                'ip': '185.22.91.44',
                'country': 'Russia',
                'asn': 'AS12345',
                'org': 'Hosting Provider LLC',
                'is_private': False,
                'risk_note': ''
            }
        """
        if ip in self._cache:
            return self._cache[ip]

        result = {
            'ip': ip,
            'country': 'Unknown',
            'asn': 'Unknown',
            'org': 'Unknown',
            'is_private': False,
            'risk_note': '',
        }

        # Check for private/reserved IPs
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                result['is_private'] = True
                result['country'] = 'Internal'
                result['org'] = 'Private Network'
                result['risk_note'] = 'Internal IP — likely legitimate traffic'
                self._cache[ip] = result
                return result
            if ip_obj.is_loopback:
                result['country'] = 'Localhost'
                result['org'] = 'Loopback'
                self._cache[ip] = result
                return result
        except ValueError:
            result['risk_note'] = 'Invalid IP address format'
            self._cache[ip] = result
            return result

        # External IP lookup via ipwhois
        try:
            from ipwhois import IPWhois
            obj = IPWhois(ip)
            rdap = obj.lookup_rdap(depth=1)

            result['asn'] = f"AS{rdap.get('asn', 'Unknown')}"
            result['org'] = rdap.get('asn_description', 'Unknown')
            result['country'] = rdap.get('asn_country_code', 'Unknown')

            # Add risk note for hosting providers
            org_lower = result['org'].lower()
            hosting_keywords = ['hosting', 'cloud', 'vps', 'server', 'data center', 'datacenter']
            if any(kw in org_lower for kw in hosting_keywords):
                result['risk_note'] = 'IP belongs to hosting/cloud provider — commonly used in attacks'

        except ImportError:
            result['risk_note'] = 'ipwhois not installed — install with: pip install ipwhois'
        except Exception as e:
            result['risk_note'] = f'Lookup failed: {str(e)[:100]}'

        self._cache[ip] = result
        return result

    def enrich_events(self, events: list) -> dict:
        """
        Enrich all unique source IPs found in a list of events.
        
        Returns:
            dict mapping IP -> enrichment data
        """
        unique_ips = set()
        for event in events:
            ip = event.get('source_ip', '')
            if ip:
                unique_ips.add(ip)

        enrichment = {}
        for ip in unique_ips:
            enrichment[ip] = self.enrich_ip(ip)

        return enrichment
