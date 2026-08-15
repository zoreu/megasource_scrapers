# -*- coding: utf-8 -*-
"""
MegaSource - UHDMovies
================================

Protocol
--------
Seguindo o protocolo do MegaSource, este arquivo define:

    TITLE, VERSION, DESCRIPTION
    get_streams(media_type: str, media_id: str, config: dict | None) -> list[dict]

media_type : "movie" | "series"
media_id   : "tt0111161" (filme) | "tt0944947:1:1" (serie: temporada: episodio)

Retorna streams com behaviorHints.proxyHeaders
"""
import requests
import json
import re
import logging
import time
from urllib.parse import urlparse, urljoin, quote, unquote, parse_qs
from bs4 import BeautifulSoup

# Configuração de logging apenas para ERROS
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)

TITLE = "UHDMovies"
VERSION = "1.0.0"
DESCRIPTION = "Filmes e Series do UHDMovies"

# Configurações
DOMAINS_URL = "https://raw.githubusercontent.com/phisher98/TVVVV/refs/heads/main/domains.json"
FALLBACK_DOMAIN = "\x68\x74\x74\x70\x73\x3a\x2f\x2f\x75\x68\x64\x6d\x6f\x76\x69\x65\x73\x2e\x70\x69\x6e\x6b"
TMDB_API_KEY = "\x31\x38\x36\x35\x66\x34\x33\x61\x30\x35\x34\x39\x63\x61\x35\x30\x64\x33\x34\x31\x64\x64\x39\x61\x62\x38\x62\x32\x39\x66\x34\x39"
TMDB_BASE_URL = "https://api.themoviedb.org/3"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Headers padrão
DEFAULT_HEADERS = {
    'User-Agent': USER_AGENT,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'en-US,en;q=0.9',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
}

class UHDMoviesResolver:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(DEFAULT_HEADERS)
        self.cached_domain = ""
        self.cache = {}

    def _get_cached(self, key):
        """Obtém item do cache"""
        return self.cache.get(key)

    def _set_cache(self, key, value):
        """Armazena item no cache"""
        self.cache[key] = value

    def _get_main_url(self):
        """Obtém a URL principal do UHDMovies (com cache)"""
        if self.cached_domain:
            return self.cached_domain
        
        try:
            response = self.session.get(DOMAINS_URL, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.cached_domain = data.get('UHDMovies', FALLBACK_DOMAIN)
                return self.cached_domain
        except Exception:
            pass
        
        self.cached_domain = FALLBACK_DOMAIN
        return self.cached_domain

    def _get_base_url(self, url):
        """Extrai a URL base"""
        try:
            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            return ""

    def _fix_url(self, url, domain):
        """Corrige URL"""
        if not url:
            return ""
        if url.startswith('http'):
            return url
        if url.startswith('//'):
            return f"https:{url}"
        if url.startswith('/'):
            return domain + url
        return f"{domain}/{url}"

    def _imdb_to_tmdb(self, imdb_id):
        """Converte IMDb ID para TMDB ID"""
        try:
            url = f"{TMDB_BASE_URL}/find/{imdb_id}?api_key={TMDB_API_KEY}&external_source=imdb_id"
            response = self.session.get(url, timeout=10)
            
            if response.status_code != 200:
                return None, None
            
            data = response.json()
            
            # Tenta filme
            results = data.get('movie_results', [])
            if results:
                return results[0].get('id'), 'movie'
            
            # Tenta série
            results = data.get('tv_results', [])
            if results:
                return results[0].get('id'), 'tv'
            
            return None, None
        except Exception as e:
            logging.error(f"Erro ao converter IMDb para TMDB: {e}")
            return None, None

    def _fetch_tmdb_details(self, tmdb_id, media_type):
        """Busca detalhes do TMDB"""
        try:
            url = f"{TMDB_BASE_URL}/{media_type}/{tmdb_id}?api_key={TMDB_API_KEY}&append_to_response=external_ids"
            
            response = self.session.get(url, timeout=10)
            if response.status_code != 200:
                return None
            
            data = response.json()
            
            return {
                'title': data.get('title' if media_type == 'movie' else 'name') or data.get('original_title' if media_type == 'movie' else 'original_name'),
                'year': (data.get('release_date' if media_type == 'movie' else 'first_air_date') or '')[:4],
                'imdb_id': data.get('external_ids', {}).get('imdb_id')
            }
        except Exception as e:
            logging.error(f"Erro ao buscar detalhes do TMDB: {e}")
            return None

    def _get_index_quality(self, text):
        """Extrai qualidade do texto"""
        if not text:
            return 'Unknown'
        
        match = re.search(r'(\d{3,4})[pP]', text)
        if match:
            return f"{match.group(1)}p"
        
        if '4K' in text.upper() or 'UHD' in text.upper():
            return '2160p'
        
        return 'Unknown'

    def _bypass_hrefli(self, url):
        """Bypass do Hrefli"""
        try:
            host = self._get_base_url(url)
            
            # Primeira requisição
            response1 = self.session.get(url, headers=DEFAULT_HEADERS, timeout=15)
            if response1.status_code != 200:
                return None
            
            html1 = response1.text
            soup1 = BeautifulSoup(html1, 'html.parser')
            
            form1 = soup1.find('form', id='landing')
            if not form1:
                return None
            
            form_url1 = form1.get('action', '')
            form_data1 = {}
            for inp in form1.find_all('input'):
                name = inp.get('name')
                value = inp.get('value', '')
                if name:
                    form_data1[name] = value
            
            # Segunda requisição
            response2 = self.session.post(
                form_url1,
                data=form_data1,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=15
            )
            if response2.status_code != 200:
                return None
            
            html2 = response2.text
            soup2 = BeautifulSoup(html2, 'html.parser')
            
            form2 = soup2.find('form', id='landing')
            if not form2:
                return None
            
            form_url2 = form2.get('action', '')
            form_data2 = {}
            for inp in form2.find_all('input'):
                name = inp.get('name')
                value = inp.get('value', '')
                if name:
                    form_data2[name] = value
            
            # Terceira requisição
            response3 = self.session.post(
                form_url2,
                data=form_data2,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=15
            )
            if response3.status_code != 200:
                return None
            
            html3 = response3.text
            soup3 = BeautifulSoup(html3, 'html.parser')
            
            # Extrai token
            script = soup3.find('script', string=re.compile(r'\?go='))
            script_text = script.text if script else ''
            
            sk_token_match = re.search(r'\?go=([^"]+)', script_text)
            if not sk_token_match:
                return None
            
            sk_token = sk_token_match.group(1)
            wp_http2 = form_data2.get('_wp_http2', '')
            
            # Quarta requisição
            response4 = self.session.get(
                f"{host}?go={sk_token}",
                headers={'Cookie': f"{sk_token}={wp_http2}"},
                timeout=15
            )
            if response4.status_code != 200:
                return None
            
            html4 = response4.text
            soup4 = BeautifulSoup(html4, 'html.parser')
            
            # Extrai redirect
            meta = soup4.find('meta', attrs={'http-equiv': 'refresh'})
            if not meta:
                return None
            
            content = meta.get('content', '')
            drive_url_match = re.search(r'url=(.+)', content)
            if not drive_url_match:
                return None
            
            drive_url = drive_url_match.group(1)
            
            # Quinta requisição
            response5 = self.session.get(drive_url, headers=DEFAULT_HEADERS, timeout=15)
            if response5.status_code != 200:
                return None
            
            html5 = response5.text
            path_match = re.search(r'replace\("([^"]+)"\)', html5)
            if not path_match or path_match.group(1) == '/404':
                return None
            
            return self._fix_url(path_match.group(1), self._get_base_url(drive_url))
            
        except Exception as e:
            logging.error(f"Erro no bypass_hrefli: {e}")
            return None

    def _extract_video_seed(self, finallink):
        """Extrai URL do Video Seed"""
        try:
            parsed = urlparse(finallink)
            host = parsed.hostname or 'video-seed.xyz'
            
            # Extrai token
            query = parse_qs(parsed.query)
            token = query.get('url', [None])[0]
            
            if not token:
                return None
            
            api_url = f"https://{host}/api"
            
            response = self.session.post(
                api_url,
                data={'keys': token},
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'x-token': host,
                    'Referer': finallink
                },
                timeout=15
            )
            
            if response.status_code != 200:
                return None
            
            text = response.text
            url_match = re.search(r'url":"([^"]+)"', text)
            
            if url_match:
                return url_match.group(1).replace('\\/', '/')
            
            return None
        except Exception as e:
            logging.error(f"Erro no extract_video_seed: {e}")
            return None

    def _extract_driveseed_page(self, url):
        """Extrai streams do Driveseed"""
        streams = []
        
        try:
            page_url = url
            
            # Se tem r?key=, faz redirect
            if 'r?key=' in url:
                response = self.session.get(url, headers=DEFAULT_HEADERS, timeout=15)
                if response.status_code == 200:
                    html = response.text
                    redirect_match = re.search(r'replace\("([^"]+)"\)', html)
                    if redirect_match:
                        page_url = self._get_base_url(url) + redirect_match.group(1)
            
            response = self.session.get(page_url, headers=DEFAULT_HEADERS, timeout=15)
            if response.status_code != 200:
                return streams
            
            html = response.text
            soup = BeautifulSoup(html, 'html.parser')
            
            base_domain = self._get_base_url(page_url)
            
            # Extrai qualidade e tamanho
            first_li = soup.find('li', class_='list-group-item')
            quality_text = first_li.text if first_li else ''
            quality = self._get_index_quality(quality_text)
            
            size_li = soup.find_all('li')
            size = size_li[2].text.replace('Size : ', '').strip() if len(size_li) > 2 else ''
            
            # Extrai links
            for a in soup.select('div.text-center > a'):
                text = a.text.lower()
                href = a.get('href', '')
                
                if not href:
                    continue
                
                if 'instant download' in text:
                    try:
                        instant_res = self.session.get(href, allow_redirects=True, timeout=15)
                        if 'url=' in instant_res.url:
                            streams.append({
                                'name': 'Driveseed Instant',
                                'url': instant_res.url.split('url=')[1],
                                'quality': quality,
                                'size': size
                            })
                    except Exception:
                        pass
                
                elif 'resume cloud' in text:
                    try:
                        cloud_url = base_domain + href
                        cloud_res = self.session.get(cloud_url, headers=DEFAULT_HEADERS, timeout=15)
                        if cloud_res.status_code == 200:
                            cloud_html = cloud_res.text
                            cloud_soup = BeautifulSoup(cloud_html, 'html.parser')
                            link = cloud_soup.find('a', class_='btn-success')
                            if link and link.get('href'):
                                streams.append({
                                    'name': 'Driveseed Cloud',
                                    'url': link.get('href'),
                                    'quality': quality,
                                    'size': size
                                })
                    except Exception:
                        pass
                
                elif 'cloud download' in text:
                    streams.append({
                        'name': 'Driveseed Cloud',
                        'url': href,
                        'quality': quality,
                        'size': size
                    })
            
            return streams
        except Exception as e:
            logging.error(f"Erro no extract_driveseed_page: {e}")
            return streams

    def _format_title(self, details, media_type, season, episode, server_name, quality_label):
        """Formata o título com quebra de linha incluindo a qualidade"""
        title = f"🎬 {details['title']}"
        
        if media_type == 'tv' and season and episode:
            title += f"\n📺 S{str(season).zfill(2)}E{str(episode).zfill(2)}"
        
        # Adiciona a qualidade em destaque
        if quality_label and quality_label != 'Unknown':
            title += f"\n📊 {quality_label}"
        else:
            title += f"\n📊 HD"
        
        title += f"\n📥 {server_name}"
        
        return title

    def resolve(self, imdb_id, media_type='movie', season=None, episode=None):
        """Resolve streams para filme ou série"""
        try:
            logging.info(f"[UHDMovies] Buscando streams para TMDB: {imdb_id}, Tipo: {media_type}")
            
            # Converte IMDb para TMDB
            tmdb_id, tmdb_type = self._imdb_to_tmdb(imdb_id)
            if not tmdb_id:
                logging.error(f"TMDB ID não encontrado para {imdb_id}")
                return []
            
            # Busca detalhes do TMDB
            details = self._fetch_tmdb_details(tmdb_id, media_type)
            if not details:
                logging.error("Detalhes do TMDB não encontrados")
                return []
            
            # Obtém URL principal
            main_url = self._get_main_url()
            
            # Busca no UHDMovies
            search_url = f"{main_url}/?s={quote(details['title'])}"
            
            response = self.session.get(search_url, timeout=15)
            if response.status_code != 200:
                logging.error("Erro na busca")
                return []
            
            search_html = response.text
            search_soup = BeautifulSoup(search_html, 'html.parser')
            
            # Encontra o link do conteúdo
            target_url = ""
            
            for article in search_soup.select('article.gridlove-post, article.latestPost'):
                title_elem = article.find('h1', class_='sanket') or article.find('h2', class_='title') or article.find('a')
                title = title_elem.text.strip() if title_elem else ''
                
                link_elem = article.find('div', class_='entry-image') or article
                href = None
                
                if link_elem:
                    a = link_elem.find('a')
                    if a:
                        href = a.get('href')
                
                if not href:
                    a = article.find('a')
                    if a:
                        href = a.get('href')
                
                if href and (details['title'].lower() in title.lower() or 
                            (details.get('imdb_id') and details['imdb_id'] in title)):
                    target_url = href
                    break
            
            if not target_url:
                logging.error("Nenhum resultado encontrado")
                return []
            
            # Obtém página do conteúdo
            page_response = self.session.get(target_url, timeout=15)
            if page_response.status_code != 200:
                logging.error("Erro ao acessar página do conteúdo")
                return []
            
            page_html = page_response.text
            soup = BeautifulSoup(page_html, 'html.parser')
            
            all_streams = []
            
            if media_type == 'movie':
                # Extrai links de filmes
                for elem in soup.select('div.entry-content > p, div.entry-content > div'):
                    text = elem.text
                    if '[' in text and ']' in text:
                        quality = self._get_index_quality(text)
                        
                        # Procura o link no próximo elemento
                        next_elem = elem.find_next_sibling()
                        href = None
                        
                        if next_elem:
                            a = next_elem.find('a', class_=re.compile(r'maxbutton-\d+|maxbutton'))
                            if a:
                                href = a.get('href')
                        
                        if not href:
                            a = elem.find('a', class_=re.compile(r'maxbutton-\d+|maxbutton'))
                            if a:
                                href = a.get('href')
                        
                        if href:
                            all_streams.append({'url': href, 'quality': quality})
            
            else:
                # Extrai links de séries
                episodes_map = {}
                current_season = season or 1
                
                for elem in soup.find_all(['pre', 'p', 'a', 'h3']):
                    text = elem.text.strip()
                    
                    # Detecta temporada
                    season_match = re.search(r'(?:season\s*|S)(\d+)', text, re.I)
                    if season_match and len(text) < 20:
                        current_season = int(season_match.group(1))
                    
                    # Detecta episódio
                    if (elem.name == 'a' or elem.find('a')) and 'episode' in text.lower():
                        if 'zip' in text.lower():
                            continue
                        
                        ep_match = re.search(r'Episode\s*(\d+)', text, re.I)
                        if ep_match:
                            real_ep = int(ep_match.group(1))
                            ep_url = elem.get('href') if elem.name == 'a' else elem.find('a').get('href')
                            
                            if ep_url:
                                key = f"{current_season}-{real_ep}"
                                if key not in episodes_map:
                                    episodes_map[key] = []
                                episodes_map[key].append(ep_url)
                
                target_key = f"{season or 1}-{episode or 1}"
                for url in episodes_map.get(target_key, []):
                    all_streams.append({'url': url, 'quality': 'Unknown'})
            
            # Processa cada stream
            final_results = []
            
            for item in all_streams:
                final_link = item['url']
                quality = item.get('quality', 'Unknown')
                
                # Bypass Hrefli
                if 'unblockedgames' in final_link:
                    final_link = self._bypass_hrefli(final_link)
                    if not final_link:
                        continue
                
                if final_link:
                    # Driveseed / Driveleech
                    if 'driveseed' in final_link or 'driveleech' in final_link:
                        streams = self._extract_driveseed_page(final_link)
                        for s in streams:
                            stream_quality = s.get('quality', quality)
                            title = self._format_title(
                                details, media_type, season, episode,
                                s.get('name', 'Driveseed'),
                                stream_quality
                            )
                            
                            final_results.append({
                                'title': title,
                                'stream': s.get('url', ''),
                                'quality': self._parse_quality(stream_quality),
                                'quality_label': stream_quality,
                                'size': s.get('size', ''),
                                'User-Agent': USER_AGENT,
                                'Referer': self._get_main_url(),
                                'Origin': self._get_main_url(),
                            })
                    
                    # Video Seed
                    elif 'video-seed' in final_link:
                        stream_url = self._extract_video_seed(final_link)
                        if stream_url:
                            stream_quality = quality
                            title = self._format_title(
                                details, media_type, season, episode,
                                'VideoSeed',
                                stream_quality
                            )
                            
                            final_results.append({
                                'title': title,
                                'stream': stream_url,
                                'quality': self._parse_quality(stream_quality),
                                'quality_label': stream_quality,
                                'size': '',
                                'User-Agent': USER_AGENT,
                                'Referer': self._get_main_url(),
                                'Origin': self._get_main_url(),
                            })
                    
                    # Link direto
                    else:
                        stream_quality = self._get_index_quality(final_link) or quality
                        title = self._format_title(
                            details, media_type, season, episode,
                            'UHDMovies',
                            stream_quality
                        )
                        
                        final_results.append({
                            'title': title,
                            'stream': final_link,
                            'quality': self._parse_quality(stream_quality),
                            'quality_label': stream_quality,
                            'size': '',
                            'User-Agent': USER_AGENT,
                            'Referer': self._get_main_url(),
                            'Origin': self._get_main_url(),
                        })
            
            # Remove duplicatas
            seen_urls = set()
            unique_streams = []
            for stream in final_results:
                url = stream.get('stream', '')
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    unique_streams.append(stream)
            
            # Ordena por qualidade
            quality_order = {'4K': 6, '2160p': 5, '1440p': 4, '1080p': 3, '720p': 2, '480p': 1, '360p': 0}
            unique_streams.sort(key=lambda x: quality_order.get(x.get('quality_label', '720p'), 0), reverse=True)
            
            return unique_streams
            
        except Exception as e:
            logging.error(f"Erro ao resolver: {e}")
            return []

    def _parse_quality(self, quality_label):
        """Converte label de qualidade para número"""
        quality_map = {
            '4K': 2160,
            '2160p': 2160,
            '1440p': 1440,
            '1080p': 1080,
            '720p': 720,
            '480p': 480,
            '360p': 360,
        }
        
        if isinstance(quality_label, str):
            match = re.search(r'(\d{3,4})', quality_label)
            if match:
                return int(match.group(1))
        
        return quality_map.get(quality_label, 720)


def get_streams(media_type, media_id, config=None):
    """
    Função principal do scraper - chamada pelo MegaSource
    """
    # Parse do media_id
    imdb_id = media_id
    season = episode = None
    
    if ":" in media_id:
        parts = media_id.split(":", 2)
        imdb_id = parts[0]
        if len(parts) > 1:
            season = int(parts[1])
        if len(parts) > 2:
            episode = int(parts[2])
    
    resolver = UHDMoviesResolver()
    
    # Busca streams conforme o tipo
    if media_type == "movie":
        streams_data = resolver.resolve(imdb_id, 'movie', None, None)
    elif media_type == "series" and season and episode:
        streams_data = resolver.resolve(imdb_id, 'tv', season, episode)
    else:
        return []
    
    if not streams_data:
        return []
    
    # Formata para o padrão do MegaSource
    result = []
    for stream in streams_data:
        url = stream.get('stream', '')
        if not url:
            continue
        
        title = stream.get('title', 'UHDMovies')
        
        result.append({
            "name": TITLE,
            "title": title,
            "url": url,
            "behaviorHints": {
                "notMyMetadata": True,
                "proxyHeaders": {
                    "request": {
                        "User-Agent": stream.get('User-Agent', USER_AGENT),
                        "Origin": stream.get('Origin', FALLBACK_DOMAIN),
                        "Referer": stream.get('Referer', FALLBACK_DOMAIN + '/'),
                    }
                },
            },
        })
    
    return result


