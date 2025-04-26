import time
import random
import threading
import sqlite3
import os
from datetime import datetime

SOURCES = ["web_server", "database", "auth_service", "network_sensor"]
EVENT_TYPES = ["login_success", "login_failure", "data_access", "error", "config_change"]

class LogCollector:
    def __init__(self, queue):
        self.queue = queue
        self.running = True

    def generate_event(self):
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "source": random.choice(SOURCES),
            "type": random.choice(EVENT_TYPES),
            "user": f"user{random.randint(1,10)}",
            "details": "Simulated event"
        }

    def run(self):
        while self.running:
            event = self.generate_event()
            self.queue.append(event)
            time.sleep(0.2)

    def stop(self):
        self.running = False

class Normalizer:
    @staticmethod
    def normalize(raw):
        return {
            "time": raw["timestamp"],
            "origin": raw["source"],
            "action": raw["type"],
            "username": raw["user"],
            "details": raw["details"]
        }

class EventStore:
    def __init__(self, db_file="siem.db"):
        self.conn = sqlite3.connect(db_file, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT,
                origin TEXT,
                action TEXT,
                username TEXT,
                details TEXT
            )
        """)
        self.conn.commit()

    def save(self, event):
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO events (time, origin, action, username, details) VALUES (?, ?, ?, ?, ?)",
            (event["time"], event["origin"], event["action"], event["username"], event["details"]) )
        self.conn.commit()

class CorrelationEngine:
    def __init__(self, alert_manager):
        self.alert_manager = alert_manager
        self.fail_counts = {}

    def process(self, event):
        user = event["username"]
        action = event["action"]

        if action == "login_failure":
            self.fail_counts[user] = self.fail_counts.get(user, 0) + 1
            if self.fail_counts[user] >= 5:
                self.alert_manager.raise_alert(
                    f"Brute-force detected for {user}: {self.fail_counts[user]} failed logins"
                )
        elif action == "login_success":
            self.fail_counts[user] = 0

        if action == "config_change" and event["origin"] == "network_sensor":
            self.alert_manager.raise_alert(
                f"Configuration change on network_sensor by {user}"
            )

class AlertManager:
    def raise_alert(self, message):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[ALERT] {now} - {message}")

class SIEM:
    def __init__(self):
        self.queue = []
        self.collector = LogCollector(self.queue)
        self.normalizer = Normalizer()
        self.store = EventStore()
        self.alert_manager = AlertManager()
        self.correlator = CorrelationEngine(self.alert_manager)

    def start(self):
        t = threading.Thread(target=self.collector.run, daemon=True)
        t.start()
        print("SIEM system started...")
        try:
            while True:
                if self.queue:
                    raw = self.queue.pop(0)
                    event = self.normalizer.normalize(raw)
                    self.store.save(event)
                    self.correlator.process(event)
                else:
                    time.sleep(0.1)
        except KeyboardInterrupt:
            self.collector.stop()
        finally:
            
            print("Exported last events and exiting.")

    def dump_last_events_to_file(self, n=10, filepath='last_events.txt'):
        """
        Сохраняет последние n событий из БД в текстовый файл (CSV-подобно) и выводит абсолютный путь.
        """
        cursor = self.store.conn.cursor()
        cursor.execute(
            "SELECT time, origin, action, username, details FROM events ORDER BY id DESC LIMIT ?", (n,)
        )
        rows = cursor.fetchall()
       
        with open(filepath, 'w', encoding='utf-8') as f:
            for row in reversed(rows):
                f.write(','.join(row) + '\n')
        abs_path = os.path.abspath(filepath)
        print(f"Saved last {n} events to {abs_path}")

if __name__ == "__main__":
    siem = SIEM()
    siem.start()
