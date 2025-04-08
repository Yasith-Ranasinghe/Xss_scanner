import re
import requests
import tldextract
import difflib
from urllib.parse import urlparse
from bs4 import BeautifulSoup

class PhishingDetector:
    def __init__(self):
        # Expanded keyword list with common phishing terms
        self.phishing_keywords = [
            "login", "password", "verify", "account", "security", "update", "banking", 
            "paypal", "ebay", "amazon", "confirm", "reset", "suspend", "unusual", 
            "activity", "alert", "unauthorized", "access", "identity", "credential",
            "validation", "expire", "ssn", "social", "secure", "official"
        ]
        
        # Expanded list of suspicious TLDs
        self.suspicious_tlds = [
            ".xyz", ".top", ".info", ".online", ".club", ".work", ".link", ".store",
            ".website", ".live", ".click", ".pw", ".tk", ".ml", ".ga", ".cf"
        ]
        
        # Common legitimate domains that are frequently impersonated
        self.legitimate_domains = [
            "google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com", 
            "paypal.com", "netflix.com", "instagram.com", "twitter.com", "linkedin.com",
            "chase.com", "bankofamerica.com", "wellsfargo.com", "capitalone.com"
        ]

    def extract_domain_info(self, url):
        """Extract domain, subdomain, and TLD using tldextract."""
        extracted = tldextract.extract(url)
        return {
            "domain": extracted.domain,
            "subdomain": extracted.subdomain,
            "tld": extracted.suffix
        }

    def check_ssl_certificate(self, url):
        """Check if the URL has a valid SSL certificate."""
        try:
            if not url.startswith("https://"):
                return False
            response = requests.get(url, timeout=5, verify=True)
            return response.ok
        except requests.exceptions.SSLError:
            return False
        except Exception:
            return False

    def detect_phishing_keywords(self, html_content):
        """Detect phishing keywords in the HTML content and return matched words."""
        matches = []
        for keyword in self.phishing_keywords:
            if re.search(rf"\b{keyword}\b", html_content, re.IGNORECASE):
                matches.append(keyword)
        return matches

    def is_suspicious_tld(self, tld):
        """Check if the TLD is suspicious."""
        return tld in self.suspicious_tlds

    def detect_typosquatting(self, domain):
        """Check if the domain is a potential typosquatting of common legitimate domains."""
        typosquatting_results = []
        
        for legit_domain in self.legitimate_domains:
            # Remove TLD for comparison
            legit_name = legit_domain.split('.')[0]
            
            # Calculate string similarity
            similarity = difflib.SequenceMatcher(None, domain, legit_name).ratio()
            
            # Detect common typosquatting patterns
            is_similar = similarity > 0.8
            has_misspelling = self._has_misspelling(domain, legit_name)
            has_character_substitution = self._has_character_substitution(domain, legit_name)
            
            if is_similar or has_misspelling or has_character_substitution:
                typosquatting_results.append({
                    "legitimate_domain": legit_domain,
                    "similarity": similarity,
                    "has_misspelling": has_misspelling,
                    "has_character_substitution": has_character_substitution
                })
                
        return typosquatting_results

    def _has_misspelling(self, domain, legitimate_domain):
        """Check for common misspellings (adding/removing/swapping letters)."""
        # Simple edit distance <= 2
        return difflib.SequenceMatcher(None, domain, legitimate_domain).ratio() > 0.7 and domain != legitimate_domain

    def _has_character_substitution(self, domain, legitimate_domain):
        """Check for character substitutions like 0 for o, 1 for l, etc."""
        substitutions = {
            'o': '0', 'i': '1', 'l': '1', 'e': '3', 'a': '4', 's': '5', 
            'g': '9', 'b': '8'
        }
        
        # Check if replacing look-alike characters makes domains match
        test_domain = domain
        for char, replacement in substitutions.items():
            test_domain = test_domain.replace(replacement, char)
            
        return test_domain == legitimate_domain or difflib.SequenceMatcher(None, test_domain, legitimate_domain).ratio() > 0.9

    def analyze_forms(self, html_content):
        """Analyze forms in the HTML content for phishing indicators."""
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = soup.find_all('form')
        
        suspicious_forms = []
        for form in forms:
            form_info = {
                'action': form.get('action', ''),
                'method': form.get('method', ''),
                'has_password_field': False,
                'has_email_field': False,
                'has_credit_card_field': False,
                'input_fields': []
            }
            
            inputs = form.find_all('input')
            for input_field in inputs:
                field_type = input_field.get('type', '')
                field_name = input_field.get('name', '')
                field_id = input_field.get('id', '')
                
                form_info['input_fields'].append({
                    'type': field_type,
                    'name': field_name,
                    'id': field_id
                })
                
                # Check for sensitive input fields
                if field_type == 'password' or 'password' in field_name.lower() or 'password' in field_id.lower():
                    form_info['has_password_field'] = True
                
                if field_type == 'email' or 'email' in field_name.lower() or 'email' in field_id.lower():
                    form_info['has_email_field'] = True
                
                if ('credit' in field_name.lower() or 'card' in field_name.lower() or 
                    'credit' in field_id.lower() or 'card' in field_id.lower()):
                    form_info['has_credit_card_field'] = True
            
            # Form with password field but no HTTPS is highly suspicious
            if form_info['has_password_field'] and (not form_info['action'].startswith('https://') and 
                                                 not form_info['action'].startswith('/')):
                form_info['is_suspicious'] = True
                suspicious_forms.append(form_info)
            
            # Form with credit card info but no HTTPS is highly suspicious
            if form_info['has_credit_card_field'] and (not form_info['action'].startswith('https://') and 
                                                    not form_info['action'].startswith('/')):
                form_info['is_suspicious'] = True
                suspicious_forms.append(form_info)
                
        return suspicious_forms

    def check_redirect_chain(self, url, max_redirects=5):
        """Check the redirect chain for suspicious behavior."""
        try:
            response = requests.get(url, timeout=5, allow_redirects=False)
            redirects = []
            redirect_count = 0
            
            while 'Location' in response.headers and redirect_count < max_redirects:
                redirect_location = response.headers['Location']
                redirects.append(redirect_location)
                
                if redirect_location.startswith('/'):
                    # Relative URL - construct absolute URL
                    parsed_url = urlparse(url)
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                    redirect_location = base_url + redirect_location
                    
                response = requests.get(redirect_location, timeout=5, allow_redirects=False)
                redirect_count += 1
                
            return {
                'redirect_count': redirect_count,
                'redirect_chain': redirects,
                'has_suspicious_redirects': self._has_suspicious_redirects(redirects)
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'redirect_count': 0,
                'redirect_chain': [],
                'has_suspicious_redirects': False
            }
    
    def _has_suspicious_redirects(self, redirect_chain):
        """Check if the redirect chain contains suspicious patterns."""
        if not redirect_chain:
            return False
            
        # Check for domain changes in redirect chain
        domains = []
        for url in redirect_chain:
            try:
                domain_info = self.extract_domain_info(url)
                full_domain = f"{domain_info['domain']}.{domain_info['tld']}"
                domains.append(full_domain)
            except:
                continue
                
        # If we have multiple domains in the chain, it might be suspicious
        return len(set(domains)) > 1
    
    def analyze_url(self, url):
        """Analyze a URL for phishing indicators."""
        domain_info = self.extract_domain_info(url)
        is_https = self.check_ssl_certificate(url)
        is_suspicious_tld = self.is_suspicious_tld(domain_info["tld"])
        typosquatting_results = self.detect_typosquatting(domain_info["domain"])
        redirect_analysis = self.check_redirect_chain(url)
        
        # Calculate phishing probability based on all indicators
        phishing_score = 0
        
        if not is_https:
            phishing_score += 0.3
        
        if is_suspicious_tld:
            phishing_score += 0.4
        
        if typosquatting_results:
            phishing_score += 0.6
            
        if redirect_analysis.get('has_suspicious_redirects', False):
            phishing_score += 0.5
            
        # Cap the score at 1.0
        phishing_score = min(phishing_score, 1.0)

        return {
            "url": url,
            "domain": domain_info["domain"],
            "subdomain": domain_info["subdomain"],
            "tld": domain_info["tld"],
            "is_https": is_https,
            "is_suspicious_tld": is_suspicious_tld,
            "typosquatting_results": typosquatting_results,
            "redirect_analysis": redirect_analysis,
            "phishing_score": phishing_score,
            "is_phishing": phishing_score > 0.5
        }

    def analyze_content(self, html_content):
        """Analyze HTML content for phishing indicators."""
        phishing_keywords = self.detect_phishing_keywords(html_content)
        suspicious_forms = self.analyze_forms(html_content)
        
        # Calculate content phishing score
        content_phishing_score = 0
        
        if phishing_keywords:
            content_phishing_score += min(0.1 * len(phishing_keywords), 0.5)
            
        if suspicious_forms:
            content_phishing_score += min(0.3 * len(suspicious_forms), 0.7)
            
        return {
            "phishing_keywords": phishing_keywords,
            "suspicious_forms": suspicious_forms,
            "content_phishing_score": content_phishing_score,
            "is_suspicious_content": content_phishing_score > 0.3
        }