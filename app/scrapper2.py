import requests
from bs4 import BeautifulSoup
import random
import time
import urllib.parse
from functools import lru_cache
import json
import concurrent.futures
try:
    from langdetect import detect
except ImportError:
    detect = None  # Fallback if not installed

# Tavily API Configuration
TAVILY_API_KEY = "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"  
TAVILY_BASE_URL = "https://api.tavily.com/search"

# Expanded User-Agent list (kept for any remaining scraping)
HEADERS_LIST = [
    {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36'},
    {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'},
    {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/112.0.0.0 Safari/537.36'},
    {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0'},
    {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15'}
]

def get_headers():
    return random.choice(HEADERS_LIST)

def safe_request(url, max_retries=3, timeout=5):
    """Generic request function for any non-API calls."""
    for attempt in range(max_retries):
        try:
            resp = requests.get(url, headers=get_headers(), timeout=timeout)
            if resp.status_code == 200:
                return resp
            elif resp.status_code == 429:
                time.sleep(random.uniform(3, 5))
            else:
                time.sleep(random.uniform(1, 3))
        except requests.RequestException as e:
            print(f"Request failed for {url}: {e}")
            time.sleep(random.uniform(1, 3))
    return None

@lru_cache(maxsize=200)
def tavily_search(query, max_results=10, search_depth="advanced"):
    if not TAVILY_API_KEY:
        print("Tavily API key not set. Skipping Tavily search.")
        return []

    params = {
        "api_key": TAVILY_API_KEY,
        "query": query,
        "search_depth": search_depth,
        "max_results": max_results,
        "include_answer": False,
        "include_images": True,
        "include_raw_content": True if search_depth == "advanced" else False
    }
    for attempt in range(3):  # Retry up to 3 times
        try:
            response = requests.post(TAVILY_BASE_URL, json=params, timeout=15)
            if response.status_code == 429:
                print("Tavily rate limit exceeded. Waiting before retrying...")
                time.sleep(random.uniform(5, 10))
                continue
            if response.status_code != 200:
                print(f"Tavily API error for query '{query}': {response.status_code} - {response.text}")
                return []
            data = response.json()
            results = []
            if "results" in data:
                for item in data["results"]:
                    title = item.get("title", "No title")
                    url = item.get("url", "#")
                    snippet = item.get("content", "")
                    text_to_check = title + " " + snippet
                    if ".cn" in url.lower() or (detect and detect(text_to_check) == "zh"):
                        continue
                    meta = {
                        "score": item.get("score", 0),
                        "images": item.get("images", []),
                        "raw_content_length": len(snippet) if "raw_content" in item else 0
                    }
                    results.append({
                        "title": title,
                        "link": url,
                        "snippet": snippet[:1000],
                        "source": "tavily",
                        "meta": meta
                    })
            print(f"Tavily results for '{query}': {len(results)} items found.")
            return results
        except requests.exceptions.RequestException as e:
            print(f"Tavily request failed for query '{query}' (attempt {attempt + 1}/3): {e}")
            if attempt < 2:
                time.sleep(random.uniform(2, 5))
            continue
    print(f"Tavily search failed for '{query}' after 3 attempts.")
    return []

# Retained some API-based sources for diversity (Wikipedia, Google Scholar via their APIs)
@lru_cache(maxsize=200)
def scrape_wikipedia(query, max_results=5):
    """Wikipedia API (unchanged, but with language filter)."""
    search_url = f"https://en.wikipedia.org/w/api.php?action=opensearch&search={urllib.parse.quote(query)}&limit={max_results}&format=json"
    response = safe_request(search_url)
    if not response:
        return []
    data = response.json()
    titles, _, _, links = data
    results = []
    for title, link in zip(titles[:max_results], links[:max_results]):
        if detect and detect(title) == "zh":
            continue
        summary_url = f"https://en.wikipedia.org/w/api.php?action=query&prop=extracts|info&exintro&explaintext&titles={urllib.parse.quote(title)}&format=json"
        summary_resp = safe_request(summary_url)
        if summary_resp:
            summary_data = summary_resp.json()
            page = next(iter(summary_data['query']['pages'].values()), {})
            snippet = page.get('extract', '')[:800]
            last_modified = page.get('touched', '')
        else:
            snippet = ''
            last_modified = ''
        results.append({
            "title": title,
            "link": link,
            "snippet": snippet,
            "source": "wikipedia",
            "last_modified": last_modified,
            "meta": {"type": "encyclopedia"}
        })
    return results

@lru_cache(maxsize=200)
def scrape_google_scholar(query, max_results=5):
    """Google Scholar scraping (kept for academic focus, but note: use Scholar API if available; this is basic scrape)."""
    url = f"https://scholar.google.com/scholar?q={urllib.parse.quote(query)}"
    response = safe_request(url)
    if not response:
        return []
    soup = BeautifulSoup(response.text, 'html.parser')
    results = []
    for result in soup.find_all('div', class_='gs_r gs_or gs_scl', limit=max_results):
        title_elem = result.find('h3', class_='gs_rt')
        link_elem = title_elem.find('a') if title_elem else None
        snippet_elem = result.find('div', class_='gs_rs')
        url = link_elem.get('href', '#') if link_elem else '#'
        title_text = title_elem.get_text().strip() if title_elem else 'No title'
        if detect and detect(title_text) == "zh":
            continue
        results.append({
            "title": title_text,
            "link": url,
            "snippet": snippet_elem.get_text().strip()[:800] if snippet_elem else '',
            "source": "google_scholar",
            "meta": {"type": "academic"}
        })
    return results

# Optional: Enhanced fetch_page_snippet for Tavily results if needed (but Tavily already provides content)
@lru_cache(maxsize=150)
def fetch_page_snippet(url, max_length=500):
    """Fallback snippet fetcher for non-Tavily sources."""
    if not url.startswith(('http://', 'https://')):
        return {'snippet': '', 'meta': {}}
    response = safe_request(url, timeout=4)
    if not response:
        return {'snippet': '', 'meta': {}}
    try:
        soup = BeautifulSoup(response.text, 'html.parser')
        meta = {
            'description': soup.find('meta', attrs={'name': 'description'})['content'] if soup.find('meta', attrs={'name': 'description'}) else '',
            'author': soup.find('meta', attrs={'name': 'author'})['content'] if soup.find('meta', attrs={'name': 'author'}) else '',
            'publish_date': soup.find('meta', attrs={'property': 'og:published_time'})['content'] if soup.find('meta', attrs={'property': 'og:published_time'}) else ''
        }
        headings = ' '.join(h.get_text().strip() for h in soup.find_all(['h1', 'h2', 'h3'])[:3])
        paragraphs = ' '.join(p.get_text().strip() for p in soup.find_all('p')[:4])
        text = headings + ' ' + paragraphs
        if detect and detect(text) == "zh":
            return {'snippet': '', 'meta': {}}
        return {'snippet': text[:max_length] + '...' if text else '', 'meta': meta}
    except Exception as e:
        print(f"Error parsing page {url}: {e}")
        return {'snippet': '', 'meta': {}}



def tavily_enhanced_scraper(search_terms, max_results=10, include_wiki=True, include_scholar=True):
    all_results = {}
    sources = []
    if include_wiki:
        sources.append(scrape_wikipedia)
    if include_scholar:
        sources.append(scrape_google_scholar)
    
    for term in search_terms:
        term_results = {}
        
        # Primary: Tavily
        tavily_results = tavily_search(term, max_results=max_results)
        print(f"Raw Tavily results for '{term}': {json.dumps(tavily_results, indent=2)[:1000]}...")
        term_results["tavily"] = tavily_results
        
        # Secondary sources
        if sources:
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(sources)) as executor:
                future_to_source = {executor.submit(source, term, max_results=max_results): source.__name__.split('_')[1] for source in sources}
                for future in concurrent.futures.as_completed(future_to_source):
                    try:
                        res = future.result()
                        src_name = future_to_source[future]
                        if res:
                            term_results[src_name] = res
                    except Exception as e:
                        print(f"Error in secondary scrape for {future_to_source[future]}: {e}")
        
        # Deduplicate and rank
        unique_results = {}
        seen_links = set()
        all_source_results = []
        for source, results in term_results.items():
            for r in results:
                link = r.get('link', '#')
                if link not in seen_links:
                    all_source_results.append((r, source))
                    seen_links.add(link)
        
        # Sort: Prioritize Tavily (high score), then others by snippet length
        def sort_key(item):
            r, src = item
            try:
                score = r['meta'].get('score', 0) if src == "tavily" else 0
                return (-score, -len(r.get('snippet', '')))
            except (KeyError, TypeError) as e:
                print(f"Sort error for {src}: {e}")
                return (0, -len(r.get('snippet', '')))
        
        sorted_results = sorted(all_source_results, key=sort_key)[:20]
        
        # Group back by source
        for r, src in sorted_results:
            if src not in unique_results:
                unique_results[src] = []
            unique_results[src].append(r)
        
        all_results[term] = unique_results
        print(f"Processed results for '{term}': {json.dumps(unique_results, indent=2)[:1000]}...")
        time.sleep(random.uniform(1.0, 2.0))
    
    print(f"Final results: {json.dumps(all_results, indent=2)[:1000]}...")
    return all_results

# Example usage:
# results = tavily_enhanced_scraper(["example query"], max_results=15, include_wiki=True, include_scholar=True)
# print(json.dumps(results, indent=2))