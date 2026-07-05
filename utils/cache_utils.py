import os
import json
import logging
import hashlib
import time

def atomic_write_json(filepath: str, data: dict) -> None:
    """
    Writes JSON data to a file atomically by writing to a temporary file first
    and then replacing the target file. Prevents cache corruption from concurrent writes.
    """
    temp_filepath = f"{filepath}.tmp.{int(time.time() * 1000)}"
    try:
        with open(temp_filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        os.replace(temp_filepath, filepath)
    except Exception as e:
        logging.error(f"Failed to atomically write {filepath}: {e}")
        # Clean up temp file if rename failed
        if os.path.exists(temp_filepath):
            try:
                os.remove(temp_filepath)
            except OSError:
                pass

def safe_read_json(filepath: str, default_value=None):
    """
    Safely reads JSON from a file. If the file is missing or corrupted,
    it returns the default_value and optionally deletes the corrupted cache.
    """
    if default_value is None:
        default_value = {}
        
    if not os.path.exists(filepath):
        return default_value
        
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logging.warning(f"Cache file {filepath} is corrupted. Resetting. Error: {e}")
        try:
            os.remove(filepath)
        except OSError:
            pass
        return default_value
    except Exception as e:
        logging.error(f"Error reading JSON from {filepath}: {e}")
        return default_value

def generate_cache_key(prefix: str, *args) -> str:
    """
    Generates a versioned cache key string. Useful to ensure caches invalidate
    when parameters (like prompt text or model version) change.
    """
    hasher = hashlib.md5()
    for arg in args:
        hasher.update(str(arg).encode('utf-8'))
    return f"{prefix}_{hasher.hexdigest()}"
