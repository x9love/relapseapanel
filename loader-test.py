import requests
import ctypes  # Для всплывающих окон

url = "http://127.0.0.1:5000/api/get_loader_version?api_key=de7f2367ad9ffb51d8627d60a0a5ea99"
dsc = '.gg/relapse'

try:
    response = requests.get(url)
    
    response.raise_for_status()
    
    response_data = response.json()
    
    if "version" in response_data:
        version = response_data["version"]
        print(f"Версия: {version}")
        
        # Допустим, нам нужно проверять, что версия 2.0
        if version == "2.0":
            print("Версия соответствует ожидаемой (2.0).")
        else:
            ctypes.windll.user32.MessageBoxW(0, f"loader version is old please download new version from {dsc}", "Error!", 0x30)
    else:
        print("Ключ 'version' не найден в ответе.")
        
except requests.exceptions.RequestException as e:
    print(f"Ошибка при запросе: {e}")
    ctypes.windll.user32.MessageBoxW(0, f"Ошибка: {e}", "Внимание", 0x10)  # Всплывающее окно с ошибкой

except ValueError as e:
    print(f"Ошибка при обработке JSON: {e}")
