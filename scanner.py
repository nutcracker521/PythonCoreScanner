import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
import re
from concurrent.futures import ThreadPoolExecutor
import sys
from typing import List, Dict, Set

class WebSecurityScanner:
    
    def __init__(self, target_url: str, max_depth: int = 3):
        
        self.url = target_url
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()
        
        colorama.init()
        
    
    def normalize_url(self, url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    def crawl(self, url: str, depth: int = 0) -> None:
        
        if depth > self.max_depth or url in self.visited_urls:
            return 
        
        try: 
            self.visited_urls.add(url)
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, "html.parser")
            
            
            
            
    
    
    

        
        