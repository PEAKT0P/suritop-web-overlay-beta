# /usr/libexec/suritop-web/utils.py
import os
import json
import logging

class LogTailer:
    def __init__(self, log_path, state_path):
        self.log_path = log_path
        self.state_path = state_path

    def _load_state(self):
        """Читает позицию и inode из pos-файла. 
        Поддерживает все старые форматы для плавной миграции."""
        if os.path.exists(self.state_path):
            try:
                with open(self.state_path, 'r') as f:
                    content = f.read().strip()
                    if not content:
                        return 0, 0
                    
                    # 1. Новый формат (JSON)
                    if content.startswith('{'):
                        data = json.loads(content)
                        return data.get('pos', 0), data.get('inode', 0)
                    
                    # 2. Формат от старого stats_collector.py (inode:offset)
                    elif ':' in content:
                        parts = content.split(':')
                        # Возвращаем (pos, inode)
                        return int(parts[1]), int(parts[0])
                    
                    # 3. Формат от старого modsec / suricata (просто число pos)
                    elif content.isdigit():
                        return int(content), 0
            except Exception as e:
                logging.error(f"Ошибка чтения state файла {self.state_path}: {e}")
        return 0, 0

    def _save_state(self, pos, inode):
        """Сохраняет пару [позиция, inode] в виде JSON"""
        try:
            os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
            with open(self.state_path, 'w') as f:
                json.dump({'pos': pos, 'inode': inode}, f)
        except Exception as e:
            logging.error(f"Ошибка записи state файла {self.state_path}: {e}")

    def read_new_lines(self):
        if not os.path.exists(self.log_path):
            return []

        try:
            stat = os.stat(self.log_path)
            curr_size = stat.st_size
            curr_inode = stat.st_ino
        except Exception as e:
            logging.error(f"Не удалось получить stat для {self.log_path}: {e}")
            return []

        pos, saved_inode = self._load_state()

        # ─── ПАНИК-РЕЖИМ: Проверяем, не трогали ли лог ───
        # Case 1: Лог обрезали на месте (> лог) -> curr_size стал меньше сохраненного pos
        # Case 2: Файл заменили (logrotate) -> curr_inode изменился
        if curr_size < pos or (saved_inode != 0 and curr_inode != saved_inode):
            logging.warning(f"Обнаружена зачистка или ротация лога {self.log_path}! Сброс позиции в 0.")
            pos = 0
            saved_inode = curr_inode

        lines = []
        try:
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(pos)
                for line in f:
                    lines.append(line)
                new_pos = f.tell()
            
            # Если всё успешно прочитали — фиксируем позицию и текущий inode
            self._save_state(new_pos, curr_inode)
        except Exception as e:
            logging.error(f"Ошибка при чтении строк из {self.log_path}: {e}")

        return lines