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
            links = soup.find_all('a', href=True)
            for link in links:
                next_url = urllib.parse.urljoin(url, link['href'])
                if next_url.startswith(self.url):
                    self.crawl(next_url, depth + 1)
                    
        except Exception as e: 
            print(f"Error crawling {url}: {str(e)}")
         
         
if __name__ == '__main__'   :
    if len(sys.argv) > 1:
        url_from_cmd = sys.argv[1]
        crawl = WebSecurityScanner(url_from_cmd)
        crawl.crawl(url_from_cmd)
        print(crawl.visited_urls)
    else:
        print("Please provde a name as a command line argument")
                
                
                
            
            
            
            
            
    
    
    

        
        