import requests
from bs4 import BeautifulSoup
import random
import time
import urllib.parse
from functools import lru_cache
import json
from langdetect import detect

# Expanded User-Agent list
HEADERS_LIST = [
    {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36'},
    {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'},
    {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/112.0.0.0 Safari/537.36'},
    {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0'},
    {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15'}
]

def get_headers():
    return random.choice(HEADERS_LIST)

def safe_request(url, max_retries=3, timeout=3):  # Reduced timeout
    """Request with retries and timeout."""
    for attempt in range(max_retries):
        try:
            resp = requests.get(url, headers=get_headers(), timeout=timeout)
            if resp.status_code == 200:
                return resp
            elif resp.status_code == 429:
                time.sleep(random.uniform(2, 4))
            else:
                time.sleep(random.uniform(1, 2))
        except requests.RequestException as e:
            print(f"Request failed for {url}: {e}")
            time.sleep(random.uniform(1, 2))
    return None

@lru_cache(maxsize=200)
def scrape_duckduckgo(query, max_results=10):
    """Scrape DuckDuckGo with snippets and clean URLs."""
    url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}"
    response = safe_request(url)
    if not response:
        print(f"DuckDuckGo scrape failed for query: {query}")
        return []

    soup = BeautifulSoup(response.text, 'html.parser')
    results = []
    for result in soup.find_all('div', class_='result__body', limit=max_results):
        title_elem = result.find('a', class_='result__a')
        snippet_elem = result.find('div', class_='result__snippet')
        url = title_elem.get('href', '#') if title_elem else '#'
        if url.startswith('//duckduckgo.com/l/?uddg='):
            url = urllib.parse.unquote(url.split('uddg=')[1].split('&')[0])
        page_snippet = fetch_page_snippet(url) if url != '#' and len(results) < 2 else ''  # Limit to 2 pages
        results.append({
            "title": title_elem.get_text() if title_elem else 'No title',
            "link": url,
            "snippet": (snippet_elem.get_text().strip() if snippet_elem else '') + ' ' + page_snippet,
            "source": "duckduckgo"
        })
        time.sleep(random.uniform(0.3, 0.7))
    print(f"DuckDuckGo results for {query}: {json.dumps(results, indent=2)[:500]}...")
    return results

@lru_cache(maxsize=100)
def scrape_wikipedia(query, max_results=3):
    """Scrape Wikipedia with summaries and metadata."""
    search_url = f"https://en.wikipedia.org/w/api.php?action=opensearch&search={urllib.parse.quote(query)}&limit={max_results}&format=json"
    response = safe_request(search_url)
    if not response:
        print(f"Wikipedia scrape failed for query: {query}")
        return []
    data = response.json()
    titles, _, _, links = data

    results = []
    for title, link in zip(titles[:max_results], links[:max_results]):
        summary_url = f"https://en.wikipedia.org/w/api.php?action=query&prop=extracts|info&exintro&explaintext&titles={urllib.parse.quote(title)}&format=json"
        summary_resp = safe_request(summary_url)
        if summary_resp:
            summary_data = summary_resp.json()
            page = next(iter(summary_data['query']['pages'].values()), {})
            snippet = page.get('extract', '')[:500]
            last_modified = page.get('touched', '')
        else:
            snippet = ''
            last_modified = ''
        results.append({
            "title": title,
            "link": link,
            "snippet": snippet,
            "source": "wikipedia",
            "last_modified": last_modified
        })
        time.sleep(random.uniform(0.5, 1.0))
    print(f"Wikipedia results for {query}: {json.dumps(results, indent=2)[:500]}...")
    return results

@lru_cache(maxsize=100)
def scrape_bing(query, max_results=5):
    """Scrape Bing with snippets."""
    url = f"https://www.bing.com/search?q={urllib.parse.quote(query)}"
    response = safe_request(url)
    if not response:
        print(f"Bing scrape failed for query: {query}")
        return []

    soup = BeautifulSoup(response.text, 'html.parser')
    results = []
    for result in soup.find_all('li', class_='b_algo', limit=max_results):
        title_elem = result.find('h2')
        link_elem = title_elem.find('a') if title_elem else None
        snippet_elem = result.find('div', class_='b_caption')
        url = link_elem.get('href', '#') if link_elem else '#'
        results.append({
            "title": title_elem.get_text() if title_elem else 'No title',
            "link": url,
            "snippet": snippet_elem.get_text().strip()[:500] if snippet_elem else '',
            "source": "bing"
        })
        time.sleep(random.uniform(0.3, 0.7))
    print(f"Bing results for {query}: {json.dumps(results, indent=2)[:500]}...")
    return results

@lru_cache(maxsize=100)
def scrape_google_scholar(query, max_results=3):
    """Scrape Google Scholar for academic papers."""
    url = f"https://scholar.google.com/scholar?q={urllib.parse.quote(query)}"
    response = safe_request(url)
    if not response:
        print(f"Google Scholar scrape failed for query: {query}")
        return []

    soup = BeautifulSoup(response.text, 'html.parser')
    results = []
    for result in soup.find_all('div', class_='gs_r gs_or gs_scl', limit=max_results):
        title_elem = result.find('h3', class_='gs_rt')
        link_elem = title_elem.find('a') if title_elem else None
        snippet_elem = result.find('div', class_='gs_rs')
        url = link_elem.get('href', '#') if link_elem else '#'
        results.append({
            "title": title_elem.get_text().strip() if title_elem else 'No title',
            "link": url,
            "snippet": snippet_elem.get_text().strip()[:500] if snippet_elem else '',
            "source": "google_scholar"
        })
        time.sleep(random.uniform(0.5, 1.0))
    print(f"Google Scholar results for {query}: {json.dumps(results, indent=2)[:500]}...")
    return results

@lru_cache(maxsize=80)
def fetch_page_snippet(url, max_length=300):
    """Fetch a short snippet from the actual page."""
    if not url.startswith(('http://', 'https://')):
        return ''
    response = safe_request(url, timeout=2)  # Reduced timeout
    if not response:
        return ''
    try:
        soup = BeautifulSoup(response.text, 'html.parser')
        paragraphs = soup.find_all('p')
        text = ' '.join(p.get_text().strip() for p in paragraphs[:2])
        return text[:max_length] + '...' if text else ''
    except Exception as e:
        print(f"Error parsing page {url}: {e}")
        return ''

def free_scraper(search_terms):
    """Aggregate results from multiple sources."""
    all_results = {}
    for term in search_terms:
        duck_results = scrape_duckduckgo(term)
        wiki_results = scrape_wikipedia(term)
        bing_results = scrape_bing(term)
        scholar_results = scrape_google_scholar(term)
        all_results[term] = {
            "duckduckgo": duck_results,
            "wikipedia": wiki_results,
            "bing": bing_results,
            "google_scholar": scholar_results
        }
        unique_results = {}
        seen_links = set()
        for source, results in all_results[term].items():
            unique_results[source] = []
            for r in results:
                if r['link'] not in seen_links:
                    unique_results[source].append(r)
                    seen_links.add(r['link'])
        all_results[term] = unique_results
        time.sleep(random.uniform(1.0, 2.0))
    print(f"Scraper results: {json.dumps(all_results, indent=2)[:1000]}...")
    return all_results