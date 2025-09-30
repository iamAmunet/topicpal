import requests
import json
from .config import GROQ_API_KEY, GROQ_ENDPOINT

def call_grok(prompt, model="gemma2-9b-it"):
    """Call Grok API for content generation."""
    if not GROQ_API_KEY:
        print("Error: GROQ_API_KEY not set.")
        return "Error: API key not configured."
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 500,
        "temperature": 0.5
    }
    try:
        print(f"Sending Grok request with prompt: {prompt[:200]}...")  # Log truncated prompt
        response = requests.post(GROQ_ENDPOINT, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        ai_response = response.json()
        print(f"Grok API response: {json.dumps(ai_response, indent=2)}")  # Log full response
        if 'choices' not in ai_response or not ai_response['choices']:
            print("Error: No choices in Grok response.")
            return "Error: Invalid API response."
        return ai_response["choices"][0]["message"]["content"].strip()
    except requests.exceptions.Timeout:
        print("Grok API timeout.")
        return "Error: API request timed out."
    except requests.exceptions.HTTPError as e:
        print(f"Grok API HTTP error: {e.response.status_code} - {e.response.text}")
        return f"Error: API returned {e.response.status_code}."
    except Exception as e:
        print(f"Grok API error: {e}")
        return f"Error generating content: {str(e)}"

def generate_keypoints(results):
    """Generate 5-10 key points from scraped data."""
    flat_results = [
        {
            "title": r.get('title', 'No title'),
            "snippet": r.get('snippet', ''),
            "source": r.get('source', 'unknown'),
            "link": r.get('link', '#')
        }
        for term in results.values()
        for source, items in term.items()
        for r in items
    ][:10]
    if not flat_results:
        print("No results for keypoints.")
        return ["- No keypoints available."]
    
    data_str = json.dumps(flat_results, indent=2)
    print(f"Keypoints input data: {data_str[:500]}...")  # Log input data
    prompt = f"""
    Generate 5-10 key points as bullet points based on this scraped data.
    Focus on the most important insights from titles and snippets, citing sources (e.g., 'Source: duckduckgo').
    And also add some of your own insights to the bullet points relavant to the scraped data
    Format: - Insight (Source: source_name)
    Data:
    {data_str}
    """
    keypoints = call_grok(prompt)
    if keypoints.startswith("Error"):
        print(f"Keypoints fallback triggered: {keypoints}")
        return [f"- {r['title']}: {r['snippet'][:100]}... (Source: {r['source']})" for r in flat_results[:5]] or ["- No keypoints available."]
    return keypoints.split('\n') if keypoints else ["- No keypoints available."]

def generate_deep_dive(results):
    """Generate a detailed analysis in 2-3 paragraphs."""
    flat_results = [
        {
            "title": r.get('title', 'No title'),
            "snippet": r.get('snippet', ''),
            "source": r.get('source', 'unknown'),
            "link": r.get('link', '#')
        }
        for term in results.values()
        for source, items in term.items()
        for r in items
    ][:15]
    if not flat_results:
        print("No results for deep dive.")
        return "No detailed information available."
    
    data_str = json.dumps(flat_results, indent=2)
    print(f"Deep dive input data: {data_str[:500]}...")  # Log input data
    prompt = f"""
    Provide a detailed analysis in 2-3 paragraphs based on this scraped data.
    Synthesize information from titles, snippets, and sources into a coherent narrative.
    and if there is not enough info in the snippets, add more information based on the title and
    Cite sources in text (e.g., 'according to duckduckgo'). and also expand on it with information relavant to the scraped data
    Data:
    {data_str}
    """
    deep_dive = call_grok(prompt)
    if deep_dive.startswith("Error"):
        print(f"Deep dive fallback triggered: {deep_dive}")
        return "\n\n".join([f"{r['title']} ({r['source']}): {r['snippet'][:200]}" for r in flat_results[:3] if r['snippet']]) or "No detailed information available."
    return deep_dive

def generate_summary(results):
    """Generate a concise summary in 1-2 paragraphs."""
    flat_results = [
        {
            "title": r.get('title', 'No title'),
            "snippet": r.get('snippet', ''),
            "source": r.get('source', 'unknown'),
            "link": r.get('link', '#')
        }
        for term in results.values()
        for source, items in term.items()
        for r in items
    ][:10]
    if not flat_results:
        print("No results for summary.")
        return "No summary available."
    
    data_str = json.dumps(flat_results, indent=2)
    print(f"Summary input data: {data_str[:500]}...")  # Log input data
    prompt = f"""
    Summarize this scraped data in 1-2 paragraphs, highlighting key findings from titles and snippets.
    but dont make it to light make it as detailed as possible starting with an intro you feel fits the topics and
    Cite sources in text (e.g., 'according to duckduckgo').
    Data:
    {data_str}
    """
    summary = call_grok(prompt)
    if summary.startswith("Error"):
        print(f"Summary fallback triggered: {summary}")
        return "; ".join([f"{r['title']} ({r['source']}): {r['snippet'][:50]}..." for r in flat_results[:3] if r['snippet']]) or "No summary available."
    return summary

def generate_sources(results):
    """Generate HTML links with snippets and sources."""
    links = []
    for term, sources in results.items():
        links.append(f"<h3>{term}</h3>")
        for source, items in sources.items():
            links.append(f"<h4>{source.capitalize()}</h4>")
            for r in items:
                url = r.get('link', '#')
                title = r.get('title', url)
                snippet = r.get('snippet', '')[:200]
                last_modified = r.get('last_modified', '')
                meta = f" ({last_modified})" if last_modified else ''
                links.append(f'<a href="{url}" target="_blank">{title}</a>{meta}<p>{snippet}</p>')
    result = "<br>".join(links) or "No sources available."
    print(f"Sources output: {result[:500]}...")  # Log output
    return result