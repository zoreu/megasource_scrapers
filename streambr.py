# -*- coding: utf-8 -*-
"""
MegaSource - StreamBR
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

TITLE = "StreamBR Scraper"
VERSION = "1.0.0"
DESCRIPTION = "Filmes e Series do StreamBR"

BASE_URL = '\x68\x74\x74\x70\x73\x3a\x2f\x2f\x62\x72\x66\x6c\x69\x78\x2e\x6c\x61\x74'
REFERER = '\x68\x74\x74\x70\x73\x3a\x2f\x2f\x62\x72\x66\x6c\x69\x78\x2e\x6c\x61\x74\x2f'
TMDB_API_KEY = '\x31\x38\x36\x35\x66\x34\x33\x61\x30\x35\x34\x39\x63\x61\x35\x30\x64\x33\x34\x31\x64\x64\x39\x61\x62\x38\x62\x32\x39\x66\x34\x39'

def imdb_to_tmdb(imdb_id):
    url = f"https://api.themoviedb.org/3/find/{imdb_id}"

    params = {
        "api_key": TMDB_API_KEY,
        "external_source": "imdb_id",
        "language": "pt-BR"
    }

    response = requests.get(url, params=params, timeout=10)
    response.raise_for_status()

    data = response.json()

    # Filme
    if data.get("movie_results"):
        item = data["movie_results"][0]
        return {
            "tip": "movie",
            "tmdb_id": item["id"],
            "name": item["title"],
            "name_original": item.get("original_title"),
            "data": item.get("release_date")
        }

    # Série
    if data.get("tv_results"):
        item = data["tv_results"][0]
        return {
            "tip": "series",
            "tmdb_id": item["id"],
            "name": item["name"],
            "name_original": item.get("original_name"),
            "data": item.get("first_air_date")
        }

    return None

def resolve_streambr(type_, name, tmdb, imdb, dubbed, season=1, episode=1):
    resolved = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0', 'Referer': REFERER}
    api = f'{BASE_URL}/best-stream-resolve?mediaType={type_}&tmdbId={tmdb}&hq=0&dubbed={dubbed}&imdbId={imdb}&season={str(season)}&episode={str(episode)}'
    try:
        r = requests.get(api,headers=headers)
        if r.status_code == 200:
            data = r.json()
            if data.get("ok", False) == True:
                streams = data.get('candidates', [])
                if streams:
                    for s in streams:
                        quality = '1080p' if s.get('quality') == 1080 else '720p'
                        url = s.get('url', '')
                        if url:
                            if not 'http' in url:
                                url = BASE_URL + url
                            if type_ == 'movie':
                                title_desc = f'📽️ {name}'
                                title_desc += f'\n📊 {quality}\n'
                            else:
                                title_desc = f"\n📺 {name} S{str(season).zfill(2)}E{str(episode).zfill(2)}"
                                title_desc += f'\n📊 {quality}\n'
                            title_desc += '🌐 Português' if dubbed == '1' else '🌐 Legendado'
                            resolved.append({
                                "name": TITLE,
                                "title": title_desc,
                                "url": url,
                                "behaviorHints": {
                                    "notMyMetadata": True,
                                    "proxyHeaders": {
                                        "request": {
                                            "User-Agent": headers['User-Agent'],
                                            "Referer": headers['Referer'],
                                        }
                                    },
                                },
                            })  
        else:
            logging.error(f"Erro ao resolver codigo: {r.status_code}")                      

    except Exception as e:
        logging.error(f"Erro ao resolver: {e}")
    return resolved


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
    
    tmdb_data = imdb_to_tmdb(imdb_id)
    
    # Busca streams conforme o tipo
    streams_data = []
    if media_type == "movie":
        #dublado
        data = resolve_streambr('movie', tmdb_data.get('name', TITLE), tmdb_data['tmdb_id'], imdb_id, '1', season='1', episode='1')
        if data:
            for i in data:
                streams_data.append(i)
        # legendado
        data2 = resolve_streambr('movie', tmdb_data.get('name', TITLE), tmdb_data['tmdb_id'], imdb_id, '0', season='1', episode='1')
        if data2:
            for i in data2:
                streams_data.append(i)                
    elif media_type == "series" and season and episode:
        #dublado
        data = resolve_streambr('tv', tmdb_data.get('name', TITLE), tmdb_data['tmdb_id'], imdb_id, '1', season=str(season), episode=str(episode))
        if data:
            for i in data:
                streams_data.append(i)
        # legendado
        data2 = resolve_streambr('tv', tmdb_data.get('name', TITLE), tmdb_data['tmdb_id'], imdb_id, '0', season=str(season), episode=str(episode))
        if data2:
            for i in data2:
                streams_data.append(i)  
    else:
        return []
    
    if not streams_data:
        return []
    
    # Formata para o padrão do MegaSource
    return streams_data

