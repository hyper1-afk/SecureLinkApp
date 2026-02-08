"""
Cyber News Module - Fetches cybersecurity news from NewsAPI and RSS feeds

Copyright (c) 2026 SecureLink. All rights reserved.
Unauthorized copying, modification, or distribution of this software is strictly prohibited.
"""

import os
import requests
import feedparser
import re
import hashlib
from datetime import datetime, timedelta
import time
import threading

# Cache for news articles
_news_cache = {
    'articles': [],
    'last_updated': None
}
_cache_lock = threading.Lock()
CACHE_DURATION = 1800  # 30 minutes for fresher news with API

# NewsAPI configuration
NEWS_API_KEY = os.getenv('NEWS_API_KEY', '')
NEWS_API_URL = 'https://newsapi.org/v2/everything'

# Cybersecurity search terms for NewsAPI
CYBER_KEYWORDS = [
    'cybersecurity',
    'data breach',
    'ransomware',
    'phishing attack',
    'malware',
    'hacking',
    'vulnerability',
    'zero-day'
]

# Fallback RSS feeds (no API key needed)
RSS_FEEDS = [
    {'url': 'https://feeds.feedburner.com/TheHackersNews', 'name': 'The Hacker News'},
    {'url': 'https://www.bleepingcomputer.com/feed/', 'name': 'BleepingComputer'},
    {'url': 'https://krebsonsecurity.com/feed/', 'name': 'Krebs on Security'},
    {'url': 'https://www.darkreading.com/rss.xml', 'name': 'Dark Reading'},
    {'url': 'https://www.securityweek.com/feed', 'name': 'SecurityWeek'}
]

# Tech-focused placeholder images
TECH_PLACEHOLDERS = [
    'https://images.unsplash.com/photo-1518770660439-4636190af475?w=400&h=200&fit=crop',
    'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=400&h=200&fit=crop',
    'https://images.unsplash.com/photo-1555949963-aa79dcee981c?w=400&h=200&fit=crop',
    'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=400&h=200&fit=crop',
    'https://images.unsplash.com/photo-1544197150-b99a580bb7a8?w=400&h=200&fit=crop',
    'https://images.unsplash.com/photo-1563986768609-322da13575f3?w=400&h=200&fit=crop',
    'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=400&h=200&fit=crop',
    'https://images.unsplash.com/photo-1510511459019-5dda7724fd87?w=400&h=200&fit=crop',
    'https://images.unsplash.com/photo-1504639725590-34d0984388bd?w=400&h=200&fit=crop',
    'https://images.unsplash.com/photo-1516110833967-0b5716ca1387?w=400&h=200&fit=crop',
    'https://images.unsplash.com/photo-1451187580459-43490279c0fa?w=400&h=200&fit=crop',
    'https://images.unsplash.com/photo-1509395176047-4a66953fd231?w=400&h=200&fit=crop',
]


def get_placeholder_image(title, url):
    """Get a consistent placeholder image based on article hash."""
    hash_input = f"{title}{url}"
    hash_value = int(hashlib.md5(hash_input.encode()).hexdigest(), 16)
    return TECH_PLACEHOLDERS[hash_value % len(TECH_PLACEHOLDERS)]


def format_relative_time(dt):
    """Format datetime as relative time string."""
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
        except:
            return 'Recently'
    
    now = datetime.now()
    if dt.tzinfo:
        dt = dt.replace(tzinfo=None)
    
    diff = now - dt
    
    if diff < timedelta(minutes=1):
        return 'Just now'
    elif diff < timedelta(hours=1):
        minutes = int(diff.total_seconds() / 60)
        return f'{minutes}m ago'
    elif diff < timedelta(days=1):
        hours = int(diff.total_seconds() / 3600)
        return f'{hours}h ago'
    elif diff < timedelta(days=7):
        days = diff.days
        return f'{days}d ago'
    else:
        return dt.strftime('%b %d')


def fetch_from_newsapi(max_articles=30):
    """Fetch news from NewsAPI.org."""
    api_key = os.getenv('NEWS_API_KEY', '')
    
    if not api_key:
        return None
    
    try:
        # Build query with cybersecurity terms
        query = ' OR '.join(CYBER_KEYWORDS[:4])  # Use first 4 terms to avoid too long query
        
        params = {
            'q': query,
            'apiKey': api_key,
            'language': 'en',
            'sortBy': 'publishedAt',
            'pageSize': min(max_articles, 100),
            'domains': 'thehackernews.com,bleepingcomputer.com,krebsonsecurity.com,darkreading.com,securityweek.com,threatpost.com,wired.com,arstechnica.com,zdnet.com,techcrunch.com'
        }
        
        response = requests.get(NEWS_API_URL, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            articles = []
            
            for item in data.get('articles', []):
                title = item.get('title', '')
                url = item.get('url', '')
                
                # Skip removed articles
                if '[Removed]' in title or not title or not url:
                    continue
                
                # Parse publication date
                pub_date = item.get('publishedAt', '')
                time_ago = format_relative_time(pub_date) if pub_date else 'Recently'
                
                # Get image
                image = item.get('urlToImage')
                if not image or 'logo' in image.lower():
                    image = get_placeholder_image(title, url)
                
                # Get source name
                source = item.get('source', {}).get('name', 'Unknown')
                
                # Get summary
                summary = item.get('description', '')
                if not summary:
                    summary = item.get('content', '')[:200] if item.get('content') else ''
                
                articles.append({
                    'title': title,
                    'url': url,
                    'source': source,
                    'time_ago': time_ago,
                    'image': image,
                    'summary': summary
                })
            
            return articles if articles else None
        else:
            print(f"NewsAPI error: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        print(f"NewsAPI fetch error: {e}")
        return None


def fetch_from_rss(max_articles=30):
    """Fallback: Fetch news from RSS feeds."""
    all_articles = []
    
    for feed_info in RSS_FEEDS:
        try:
            feed = feedparser.parse(feed_info['url'])
            
            for entry in feed.entries[:10]:  # Limit per feed
                try:
                    title = entry.get('title', '').strip()
                    url = entry.get('link', '').strip()
                    
                    if not title or not url:
                        continue
                    
                    # Parse date
                    pub_date = datetime.now()
                    if hasattr(entry, 'published_parsed') and entry.published_parsed:
                        pub_date = datetime(*entry.published_parsed[:6])
                    elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                        pub_date = datetime(*entry.updated_parsed[:6])
                    
                    # Get summary
                    summary = entry.get('summary', '') or entry.get('description', '')
                    if summary:
                        # Strip HTML tags
                        summary = re.sub(r'<[^>]+>', '', summary)[:200]
                    
                    # Get image from entry or use placeholder
                    image = None
                    if hasattr(entry, 'media_content') and entry.media_content:
                        for media in entry.media_content:
                            if media.get('url'):
                                image = media.get('url')
                                break
                    
                    if not image:
                        image = get_placeholder_image(title, url)
                    
                    all_articles.append({
                        'title': title,
                        'url': url,
                        'source': feed_info['name'],
                        'time_ago': format_relative_time(pub_date),
                        'published_datetime': pub_date,
                        'image': image,
                        'summary': summary
                    })
                    
                except Exception as e:
                    continue
                    
        except Exception as e:
            print(f"RSS feed error ({feed_info['name']}): {e}")
            continue
    
    # Sort by publication date
    all_articles.sort(key=lambda x: x.get('published_datetime', datetime.min), reverse=True)
    
    # Clean up and return
    result = []
    for article in all_articles[:max_articles]:
        result.append({
            'title': article['title'],
            'url': article['url'],
            'source': article['source'],
            'time_ago': article['time_ago'],
            'image': article['image'],
            'summary': article.get('summary', '')
        })
    
    return result if result else None


def get_cyber_news(max_articles=20, force_refresh=False):
    """
    Get cybersecurity news with caching.
    Uses NewsAPI as primary source, falls back to RSS feeds.
    
    Args:
        max_articles: Maximum number of articles to return
        force_refresh: Force refresh the cache
        
    Returns:
        dict with 'success', 'articles' list, and 'source'
    """
    global _news_cache
    
    with _cache_lock:
        now = time.time()
        
        # Check if cache is valid
        if (not force_refresh and 
            _news_cache['last_updated'] and 
            (now - _news_cache['last_updated']) < CACHE_DURATION and
            _news_cache['articles']):
            return {
                'success': True,
                'articles': _news_cache['articles'][:max_articles],
                'source': 'cache'
            }
        
        # Try NewsAPI first
        articles = fetch_from_newsapi(max_articles)
        source = 'newsapi'
        
        # Fallback to RSS if NewsAPI fails
        if not articles:
            articles = fetch_from_rss(max_articles)
            source = 'rss'
        
        if articles:
            _news_cache['articles'] = articles
            _news_cache['last_updated'] = now
            return {
                'success': True,
                'articles': articles[:max_articles],
                'source': source
            }
        
        # Return cached articles if everything fails
        if _news_cache['articles']:
            return {
                'success': True,
                'articles': _news_cache['articles'][:max_articles],
                'source': 'cache'
            }
        
        return {
            'success': False,
            'error': 'Unable to fetch news from any source',
            'articles': []
        }
