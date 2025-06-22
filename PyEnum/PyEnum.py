#!/usr/bin/env python3
"""
PowerEnum - Windows Enumeration for Privilege Escalation (Level 1 & 2)
Python version of the PowerShell script for enumeration/scanning possible 
permissions flaws or vulnerabilities in improper system configurations.

Usage:
    python powerenum.py                     # Default enumeration
    python powerenum.py --credentials       # Look for credentials
    python powerenum.py --credentials --extensions ".txt,.xml"  # Custom extensions
    python powerenum.py --search --extensions ".txt,.xml"      # Search files
    python powerenum.py --help              # Show help
"""

import os
import re
import subprocess
import argparse
import winreg
import platform
import socket
import getpass
from pathlib import Path
import glob
from datetime import datetime


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    ORANGE = '\033[38;5;208m'
    DARKYELLOW = '\033[33m'
    DARKRED = '\033[31m'
    RESET = '\033[0m'


def write_color(text, color=Colors.WHITE):
    # -> Print colored text
    print(f"{color}{text}{Colors.RESET}", end='')


def print_separator():
    print("=" * 54)


def search_files_for_sensitive_data(look_for_credentials=False, extensions=None):
    # -> Search files for sensitive data like passwords and usernames
    
    if extensions and ',' in extensions:
        extensions = [ext.strip() for ext in extensions.split(',')]
        extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in extensions]
    
    patterns = []
    
    if look_for_credentials:
        patterns = [
            r"password\s*[:=]\s*.+",
            r"senha\s*[:=]\s*.+",
            r"pass.*[=:].+",
            r"pwd.*[=:].+",
            r"secret\s*[:=]\s*.+",
            r"client[_\-]?secret\s*[:=]\s*.+",
            r"api[_\-]?key\s*[:=]\s*.+",
            r"access[_\-]?token\s*[:=]\s*.+",
            r"bearer\s+[a-zA-Z0-9\-_=]+\.*[a-zA-Z0-9\-_=]*",
            r"authorization\s*[:=]?\s*(Basic|Bearer)?\s+[a-zA-Z0-9\-\._~\+\/]+=*",
            r"user(name)?\s*[:=]\s*.+",
            r"login\s*[:=]\s*.+",
            r"usuario\s*[:=]\s*.+",
            r"username[=:].+",
            r"user[=:].+",
            r"login[=:].+",
            r"net user .+ /add",
            r"utilisateur\s*[:=]\s*.+",
            r"usuário\s*[:=]\s*.+",
            r"benutzer\s*[:=]\s*.+",
            r"user id\s*[:=]\s*.+",
            r"username\s*[:=]\s*.+",
            r"account\s*[:=]\s*.+",
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}",
            r"((key|api|token|secret|password)[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z_=\-]{8,64})['\"]"
        ]
    
    if extensions:
        text_extensions = extensions
    else:
        text_extensions = ['.txt', '.log', '.ini', '.conf', '.xml', '.html', '.htm', '.csv', '.json', '.env']
    
    ignore_names = ['license', 'eula', 'about', 'copyright', 'readme', 'strings', 'locales', 'messages']
    max_lines = 40
    max_line_length = 300
    
    #-> Get all drives
    drives = [f"{chr(i)}:\\" for i in range(ord('A'), ord('Z')+1) if os.path.exists(f"{chr(i)}:\\")]
    
    for drive in drives:
        try:
            for root, dirs, files in os.walk(drive):
                
                for file in files:
                    file_path = os.path.join(root, file)
                    file_name, file_ext = os.path.splitext(file)
                    
                    if (file_ext.lower() in text_extensions and 
                        file_name.lower() not in ignore_names):
                        
                        matches_found = []
                        line_count = 0
                        limit_reached = False
                        
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                for line in f:
                                    if len(line) > max_line_length:
                                        continue
                                    
                                    for pattern in patterns:
                                        if re.search(pattern, line, re.IGNORECASE):
                                            matches_found.append(line.strip())
                                            line_count += 1
                                            break
                                    
                                    if line_count >= max_lines:
                                        limit_reached = True
                                        break
                        except:
                            continue
                        
                        if matches_found:
                            write_color(f"\n[!] Potential matches in file: {file_path}\n", Colors.RED)
                            for match in set(matches_found):
                                write_color(f"     > {match}\n", Colors.DARKYELLOW)
                            
                            if limit_reached:
                                write_color("     [!] File has reached the 40-line limit. Output canceled.\n", Colors.MAGENTA)
        
        except Exception as e:
            write_color(f"Could not search in drive {drive}: {e}\n", Colors.RED)


def search_files_by_extension(extensions):
    # -> Search for files by extension
    
    if not extensions:
        write_color("You must specify extensions when using search files.\n", Colors.RED)
        return
    
    if ',' in extensions:
        extensions = [ext.strip() for ext in extensions.split(',')]
        extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in extensions]
    
    drives = [f"{chr(i)}:\\" for i in range(ord('A'), ord('Z')+1) if os.path.exists(f"{chr(i)}:\\")]
    
    for drive in drives:
        try:
            for root, dirs, files in os.walk(drive):
                
                for file in files:
                    file_path = os.path.join(root, file)
                    _, file_ext = os.path.splitext(file)
                    
                    if file_ext.lower() in extensions:
                        try:
                            stat = os.stat(file_path)
                            size = stat.st_size
                            mtime = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                            print(f"{file_path:<80} {size:<12} {mtime}")
                        
                        except:
                            continue
       
        except Exception as e:
            write_color(f"Could not search in drive {drive}: {e}\n", Colors.RED)


def get_clipboard_content():
    # -> Get clipboard content (Windows only)
    
    try:
        import tkinter as tk
        root = tk.Tk()
        root.withdraw()
        clipboard_content = root.clipboard_get()
    
        root.destroy()
        
        if clipboard_content:
            print(clipboard_content)
        else:
            print("The clipboard is empty.")
    
    except Exception as e:
        print(f"An error occurred while accessing the clipboard: {e}")


def get_antivirus_product():
    # -> Get antivirus information using WMI
    
    try:
        import wmi
        
        c = wmi.WMI(namespace="root\\SecurityCenter2")
        av_products = c.AntiVirusProduct()
        
        if not av_products:
            write_color("No antivirus products found.\n", Colors.RED)
            return
        
        for av in av_products:
            state_map = {
                262144: ("Up to date", "Disabled"),
                262160: ("Out of date", "Disabled"), 
                266240: ("Up to date", "Enabled"),
                266256: ("Out of date", "Enabled"),
                393216: ("Up to date", "Disabled"),
                393232: ("Out of date", "Disabled"),
                393488: ("Out of date", "Disabled"),
                397312: ("Up to date", "Enabled"),
                397328: ("Out of date", "Enabled"),
                397584: ("Out of date", "Enabled")
            }
            
            def_status, rt_status = state_map.get(av.productState, ("Unknown", "Unknown"))
            
            print(f"Name: {av.displayName}")
            print(f"Product GUID: {av.instanceGuid}")
            print(f"Product Executable: {av.pathToSignedProductExe}")
            print(f"Reporting Exe: {av.pathToSignedReportingExe}")
            print(f"Definition Status: {def_status}")
            print(f"Real-time Protection Status: {rt_status}")
            
            print("-" * 50)
            print("")
            
    except ImportError:
        write_color("WMI module not available. Install pywin32 for full antivirus detection.\n", Colors.RED)
    
    except Exception as e:
        write_color(f"Error getting antivirus info: {e}\n", Colors.RED)


def check_hotfixes():
    # -> List installed hotfixes
    
    try:
        result = subprocess.run(['wmic', 'qfe', 'get', 'HotFixID,InstalledOn', '/format:csv'], 
                              capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')[1:]  # Skip header

            for line in lines:
                if line.strip():
                    parts = line.split(',')

                    if len(parts) >= 2:
                        print(f"HotFixID: {parts[1]:<15} InstalledOn: {parts[2] if len(parts) > 2 else 'N/A'}")
            print("")

        else:
            write_color("Could not retrieve hotfix information.\n", Colors.RED)

    except Exception as e:
        write_color(f"Error checking hotfixes: {e}\n", Colors.RED)


def check_registry_key(key_path, key_name):
    # -> Check if registry key is enabled
    
    try:
        if key_path.startswith('HKLM'):
            hkey = winreg.HKEY_LOCAL_MACHINE
            subkey = key_path.replace('HKLM:\\', '').replace('\\', '\\')
        
        elif key_path.startswith('HKCU'):
            hkey = winreg.HKEY_CURRENT_USER
            subkey = key_path.replace('HKCU:\\', '').replace('\\', '\\')
        
        else:
            write_color(f"Unsupported registry hive in {key_path}\n", Colors.RED)
            return
        
        try:
            with winreg.OpenKey(hkey, subkey) as key:
                value, _ = winreg.QueryValueEx(key, key_name)
                
                if key_name == "CACHEDLOGONSCOUNT":
                    return str(value)
                
                if value == 0:
                    return f"{Colors.YELLOW}[0] Disabled{Colors.RESET}"
                elif value == 1:
                    return f"{Colors.GREEN}[1] Enabled/Found!!{Colors.RESET}"
                else:
                    return f"{Colors.YELLOW}Unexpected key value: {value}{Colors.RESET}"
                    
        except FileNotFoundError:
            return f"{Colors.RED}Registry path not found: {key_path}{Colors.RESET}"
        
        except Exception as e:
            return f"{Colors.RED}Error reading registry value: {e}{Colors.RESET}"
            
    except Exception as e:
        return f"{Colors.RED}Error accessing registry: {e}{Colors.RESET}"


def check_lsa():
    # -> Check LSA protection
    
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                           r"SYSTEM\CurrentControlSet\Control\LSA") as key:
            value, _ = winreg.QueryValueEx(key, "RunAsPPL")
            
            if value == 2:
                return "Enabled without UEFI Lock"
            
            elif value == 1:
                return "Enabled with UEFI Lock"
            
            elif value == 0:
                return f"{Colors.GREEN}Protection is Disabled!!{Colors.RESET}"
            
            else:
                return f"Unexpected registry value: {value}"
                
    except FileNotFoundError:
        return f"{Colors.RED}The system was unable to find the specified registry value{Colors.RESET}"
    
    except Exception as e:
        return f"{Colors.RED}Error checking LSA: {e}{Colors.RESET}"


def check_uac_settings():
    # -> Check UAC settings

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            value, _ = winreg.QueryValueEx(key, "EnableLUA")
            
            if value == 1:
                return "EnableLua is set to 1. UAC Features are active!"
            else:
                return f"{Colors.GREEN}EnableLUA is not active!!{Colors.RESET}"
                
    except Exception as e:
        return f"{Colors.RED}Could not read EnableLUA setting: {e}{Colors.RESET}"


def check_laps_and_credential_guard():
    # -> Check LAPS and Credential Guard

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\LSA") as key:
            value, _ = winreg.QueryValueEx(key, "LsaCfgFlags")
            
            if value == 2:
                print("Value: 2 - Credential Guard Enabled (without UEFI Lock)")
            
            elif value == 1:
                print("Value: 1 - Credential Guard Enabled (with UEFI Lock)")
            
            elif value == 0:
                write_color("Value: 0 - Credential Guard Disabled!\n", Colors.GREEN)
            
            else:
                write_color(f"LsaCfgFlags: Unknown value - {value}\n", Colors.RED)
                
    except Exception as e:
        write_color(f"Could not access LSA registry key (LsaCfgFlags): {e}\n", Colors.RED)

    #-> Check LAPS
    
    write_color("\nLAPS (Local Admin Password Solution) Check: ", Colors.YELLOW)
    laps_paths = [
        r"C:\Program Files\LAPS\CSE\Admpwd.dll",
        r"C:\Program Files (x86)\LAPS\CSE\Admpwd.dll"
    ]
    
    laps_found = False
    for path in laps_paths:
        
        if os.path.exists(path):
            write_color(f"LAPS DLL found: {path}\n", Colors.GREEN)
            laps_found = True
    
    if not laps_found:
        write_color("LAPS DLL not found on this machine.\n", Colors.RED)
    
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\Microsoft Services\AdmPwd") as key:
            value, _ = winreg.QueryValueEx(key, "AdmPwdEnabled")
            
            if value == 1:
                write_color("LAPS GPO is enabled via registry.\n", Colors.GREEN)
            else:
                write_color("LAPS GPO found but not enabled.\n", Colors.ORANGE)
                
    except Exception:
        write_color("LAPS GPO registry key not found.\n", Colors.RED)


def get_installed_applications():
    # -> Get installed applications from registry

    apps = []
    
    registry_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")
    ]
    
    for hkey, path in registry_paths:
        try:
            with winreg.OpenKey(hkey, path) as key:
                i = 0
    
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
    
                            try:
                                display_name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                                
                                try:
                                    display_version, _ = winreg.QueryValueEx(subkey, "DisplayVersion")
                                except:
                                    display_version = "N/A"
                                
                                try:
                                    publisher, _ = winreg.QueryValueEx(subkey, "Publisher")
                                except:
                                    publisher = "N/A"
                                
                                try:
                                    install_date, _ = winreg.QueryValueEx(subkey, "InstallDate")
    
                                    if len(install_date) == 8 and install_date.isdigit():
                                        install_date = f"{install_date[:4]}-{install_date[4:6]}-{install_date[6:8]}"
                                except:
                                    install_date = "N/A"
                                
                                apps.append({
                                    'name': display_name,
                                    'version': display_version,
                                    'publisher': publisher,
                                    'install_date': install_date
                                })
                            except:
                                pass
                        i += 1
    
                    except OSError:
                        break
    
        except:
            continue
    
    if apps:
        apps.sort(key=lambda x: x['name'])
        print(f"{'Application':<40} {'Version':<15} {'Publisher':<30} {'Install Date'}")
        print("-" * 100)
    
        for app in apps:
            print(f"{app['name'][:39]:<40} {app['version'][:14]:<15} {app['publisher'][:29]:<30} {app['install_date']}")
        print("")

    else:
        write_color("No applications found.\n", Colors.RED)


def get_recently_run_commands():
    # -> Get recently run commands from various sources
    
    write_color("\nHKCU recent commands: ", Colors.BLUE)
    
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU") as key:
            i = 0
            entries = []
            
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    if name != "MRUList":
                        entries.append(f"{name} : {value}")
                    i += 1
            
                except OSError:
                    break
            
            if entries:
                for entry in entries:
                    print(f"\n{entry}")
            else:
                write_color("\n[!] Empty!", Colors.DARKYELLOW)
    except:
        write_color("\n[X] Could not retrieve RunMRU registry key.", Colors.RED)

    write_color("\n\nPowerShell History (PSReadLine):\n", Colors.BLUE)
    ps_history_path = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
    
    if os.path.exists(ps_history_path):
        try:
            with open(ps_history_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                for line in lines[-20:]:
                    print(line.strip())
        except:
            write_color("Error reading PowerShell history.", Colors.RED)
    else:
        write_color("No PowerShell history file found.", Colors.RED)

    write_color("\nRecently Opened Files (RecentDocs) (Might be interesting):\n", Colors.BLUE)
    
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs") as key:
            i = 0
    
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, subkey_name) as subkey:
                        j = 0
    
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(subkey, j)
    
                                if name.isdigit():
                                    try:
                                        decoded = value.decode('utf-16le', errors='ignore').replace('\x00', '')
                                        if decoded.strip():
                                            print(decoded.strip())
                                    except:
                                        pass
                                j += 1
    
                            except OSError:
                                break
                    i += 1
    
                except OSError:
                    break
    
    except:
        write_color("RecentDocs registry key not found.", Colors.RED)

    write_color("\nExecutables from Prefetch Folder (Might be interesting):\n", Colors.BLUE)
    prefetch_path = os.path.expandvars(r"%SystemRoot%\Prefetch")
    
    if os.path.exists(prefetch_path):
        try:
            pf_files = glob.glob(os.path.join(prefetch_path, "*.pf"))[:20]
            for pf_file in pf_files:
                print(os.path.basename(pf_file))
        except:
            write_color("[X] Could not access Prefetch folder. Administrator privileges might be required.\n", Colors.RED)
    
    else:
        write_color("Prefetch folder not accessible or disabled.", Colors.RED)


def check_permissions(target):
    # -> Check permissions on a target path

    if not os.path.exists(target):
        write_color(f"Path not found: {target}\n", Colors.RED)
        return
    
    try:
        #-> Basic permission check - try to write
        if os.path.isdir(target):
            test_file = os.path.join(target, "test_write_permission.tmp")
            
            try:
                with open(test_file, 'w') as f:
                    f.write("test")
            
                os.remove(test_file)
                write_color(f"\n\n[!] Potential misconfigured access\n", Colors.GREEN)
                write_color(f"\n -> ", Colors.YELLOW)
                write_color(f"Current user has write access to '{target}'\n\n", Colors.WHITE)
            
                return
            
            except:
                pass
        
        #-> For files, check if we can modify
        if os.path.isfile(target):
            
            if os.access(target, os.W_OK):
                write_color(f"\n\n[!] Potential misconfigured access\n", Colors.GREEN)
                write_color(f"\n -> ", Colors.YELLOW)
                write_color(f"Current user has write access to '{target}'\n\n", Colors.WHITE)
                
                return
        
        write_color(f"\nNo concerning permissions found for {target}\n", Colors.RED)
        
    except Exception as e:
        write_color(f"Error checking permissions for {target}: {e}\n", Colors.RED)


def check_scheduled_tasks_custom():
    
    import xml.etree.ElementTree as ET
    from win32com.client import Dispatch

    try:
        scheduler = Dispatch('Schedule.Service')
        scheduler.Connect()

        folders = [scheduler.GetFolder('\\')]
        tasks = []

        while folders:
            folder = folders.pop(0)
            folders.extend([folder.GetFolder(f.Name) for f in folder.GetFolders(0)])
            
            for task in folder.GetTasks(1):
                if not task.Path.lower().startswith('\\microsoft'):
                    tasks.append(task)

        for task in tasks:
            xml = task.Xml
            root = ET.fromstring(xml)

            ns = {'ns': 'http://schemas.microsoft.com/windows/2004/02/mit/task'}
            actions_node = root.find('.//ns:Actions', ns)
            
            if actions_node is None:
                continue

            actions = [a.find('ns:Command', ns).text for a in actions_node if a.find('ns:Command', ns) is not None]
            if not actions:
                continue

            for action in actions:
                #-> Resolve path
                resolved = action.replace('"', '')
                for var in ['windir', 'SystemRoot', 'localappdata', 'appdata', 'UserProfile']:
                    resolved = resolved.replace(f"%{var}%", os.environ.get(var.upper(), ''))

                print(f"\n[!] Would check permissions on: {resolved}")

                write_color(f"\n\nTaskName: {task.Name}\n", Colors.CYAN)
                print("-" * 44)
                print(f"LastResult : {task.LastRunTime}")
                print(f"NextRun    : {task.NextRunTime}")
                print(f"Status     : {task.State}")
                print(f"Command    : {action}")

        print("")

    except Exception as e:
        write_color(f"Failed to enumerate scheduled tasks: {e}", Colors.RED)


def check_scheduled_tasks_access():
    # -> Check access to scheduled tasks
    
    tasks_path = r"C:\Windows\System32\Tasks"
    
    try:
        if os.path.exists(tasks_path) and os.listdir(tasks_path):
            write_color("Access confirmed!! Proceed from here:\n", Colors.GREEN)
            write_color(f"-> {tasks_path}\n\n", Colors.BLUE)
            
            for item in os.listdir(tasks_path):
                full_path = os.path.join(tasks_path, item)
                print(f" - {full_path}\n")
    
    except PermissionError:
        write_color(f"\nNo admin access to {tasks_path}. Listing scheduled tasks instead...\n", Colors.RED)
        check_scheduled_tasks_custom()


def get_process_info():
    # -> Get process information and check permissions

    try:
        result = subprocess.run(['wmic', 'process', 'get', 'ExecutablePath', '/format:csv'], capture_output=True, text=True, shell=True)
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            process_paths = set()
            
            for line in lines:
        
                if line.strip():
                    parts = line.split(',')
                    if len(parts) >= 2 and parts[1].strip():
                        process_paths.add(parts[1].strip())
            
            for process_path in process_paths:
        
                if process_path and os.path.exists(process_path):
                    write_color(f"\n-> ", Colors.YELLOW)
                    print(f"Process Path: {process_path}")
                    check_permissions(process_path)
        
        else:
            write_color("Could not retrieve process information.\n", Colors.RED)
    
    except Exception as e:
        write_color(f"Error getting process info: {e}\n", Colors.RED)
        print("")


def check_values(value, label):
    # -> Check and display registry values

    if value is None or value == "":
        write_color(f"{label}: No Value has been found!\n", Colors.RED)
    else:
        print(f"{label}: {value}")


def get_wifi_passwords():
    # -> Get saved WiFi passwords
    
    try:
        # -> Get WiFi profiles
        result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], capture_output=True, text=True, shell=True)
        
        if result.returncode == 0:
            profiles = []
            for line in result.stdout.split('\n'):
        
                if 'All User Profile' in line:
                    profile = line.split(':')[1].strip()
                    profiles.append(profile)
            
            # -> Get passwords for each profile
            for profile in profiles:
                try:
                    cmd = ['netsh', 'wlan', 'show', 'profile', f'name={profile}', 'key=clear']
                    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
                    
                    if result.returncode == 0:
                        print(f"\nProfile: {profile}")
                        print(result.stdout)
                
                except:
                    continue
    
    except Exception as e:
        write_color(f"Error getting WiFi passwords: {e}\n", Colors.RED)


def get_remote_sessions():
    
    try:
        result = subprocess.run(['quser'], capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            print(result.stdout)
        else:
            print("Failed to get remote sessions (quser not available).")
    
    except Exception as e:
        print(f"Error getting remote sessions: {e}")


def get_smb_shares():
    
    try:
        result = subprocess.run(['net', 'share'], capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            print(result.stdout)
        else:
            print("Failed to list SMB shares.")
    
    except Exception as e:
        print(f"Error listing SMB shares: {e}")


def get_smb_share_permissions():
    
    try:
        # -> 'net share' provides share names; we try to get permissions via icacls
    
        result = subprocess.run(['net', 'share'], capture_output=True, text=True, shell=True)
        if result.returncode != 0:
            print("Could not retrieve shares to get permissions.")
            return

        lines = result.stdout.splitlines()
        shares = []
    
        for line in lines:
            if 'Disk' in line:
                parts = line.split()
    
                if parts:
                    shares.append(parts[0])

        for share in shares:
            path_cmd = subprocess.run(['net', 'share', share], capture_output=True, text=True, shell=True)
            path = ""
    
            for line in path_cmd.stdout.splitlines():
                if "Path" in line:
                    path = line.split("Path")[1].strip()
                    break

            if path:
                print(f"\nPermissions for {share} ({path}):")
                perms = subprocess.run(['icacls', path], capture_output=True, text=True, shell=True)
                print(perms.stdout)
 
            else:
                print(f"Could not determine path for share {share}")

    except Exception as e:
        print(f"Error retrieving SMB share permissions: {e}")


def main():

    parser = argparse.ArgumentParser(description='PowerEnum - Windows Enumeration Script')
    parser.add_argument('--credentials', action='store_true', 
                       help='Look for possible passwords and usernames')
    parser.add_argument('--search', action='store_true',
                       help='Search for files by extension')
    parser.add_argument('--extensions', type=str,
                       help='File extensions to search (comma-separated)')
    
    args = parser.parse_args()
    
    if args.credentials:

        write_color("[+] Searching for passwords and usernames...:\n", Colors.CYAN)

        if args.extensions:
            write_color("-> ", Colors.YELLOW)
            write_color(f"Selected Extensions: {args.extensions}\n", Colors.CYAN)

        search_files_for_sensitive_data(look_for_credentials=True, extensions=args.extensions)

        return
    
    if args.search:

        if not args.extensions:
            write_color("You must specify --extensions when using --search.\n", Colors.RED)
            return

        write_color(f"\n[+] Searching for files with extensions: {args.extensions}\n", Colors.CYAN)
        search_files_by_extension(args.extensions)

        return
    
    # System Information
    os_info = platform.platform()
    hostname = socket.gethostname()
    current_user = getpass.getuser()
    
    try:
        result = subprocess.run(['net', 'user'], capture_output=True, text=True, shell=True)
        users = []

        if result.returncode == 0:
            lines = result.stdout.split('\n')

            for line in lines:
                if line.strip() and not line.startswith('User accounts') and not line.startswith('The command') and not line.startswith('-'):
                    users.extend([u.strip() for u in line.split() if u.strip()])

    except:
        users = ["Unable to enumerate"]
    
    try:
        home_folders = [d for d in os.listdir(r'C:\Users') if os.path.isdir(os.path.join(r'C:\Users', d))]
    except:
        home_folders = ["Unable to access"]

    print_separator()
    print(f"\n{Colors.MAGENTA}Os Info: {Colors.RESET}{os_info}")
    print(f"\n{Colors.MAGENTA}Hostname: {Colors.RESET}{hostname}")
    print(f"\n{Colors.MAGENTA}Home Folders: {Colors.RESET}{home_folders}")
    print(f"\n{Colors.MAGENTA}Current Logged User: {Colors.RESET}{current_user}\n")

    print_separator()
    write_color("\nRemote Sessions:\n", Colors.YELLOW)
    get_remote_sessions()

    print_separator()
    write_color("\nCurrent Privileges:\n\n", Colors.MAGENTA)
    subprocess.run(["whoami", "/priv"], shell=True)
    print("")

    print_separator()
    write_color("\nAntivirus:\n\n", Colors.MAGENTA)
    get_antivirus_product()

    print_separator()
    write_color("\nInstalled Applications:\n\n", Colors.MAGENTA)
    get_installed_applications()

    print_separator()
    write_color("\nProcess Info / Permissions:\n", Colors.MAGENTA)
    get_process_info()

    print_separator()
    write_color("\nChecking access to scheduled tasks folder:\n", Colors.MAGENTA)
    check_scheduled_tasks_access()

    print_separator()
    write_color("\nHotFixes:\n", Colors.YELLOW)
    check_hotfixes()

    print_separator()
    write_color("\nAlwaysInstallElevated (HKCU): ", Colors.YELLOW)
    print(check_registry_key('HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer', 'AlwaysInstallElevated'))

    write_color("\nAlwaysInstallElevated (HKLM): ", Colors.YELLOW)
    print(check_registry_key('HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer', 'AlwaysInstallElevated'))

    write_color("\nWDigest (LSASS Plain-Text Password Storage): ", Colors.YELLOW)
    print(check_registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest', 'UseLogonCredential'))

    write_color("\nCached WinLogon Credentials: ", Colors.YELLOW)
    print(check_registry_key('HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'CACHEDLOGONSCOUNT'))

    write_color("\nSNMP Passwords: ", Colors.YELLOW)
    print(check_registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SNMP', ''))

    write_color("\nWinVNC Passwords: ", Colors.YELLOW)
    print(check_registry_key('HKCU:\\Software\\ORL\\WinVNC3', 'Password'))

    write_color("\nLSA Protection:\n", Colors.YELLOW)
    print(check_lsa())

    write_color("\nChecking UAC Settings:\n", Colors.YELLOW)
    print(check_uac_settings())

    write_color("\nCredential Guard Check:\n", Colors.YELLOW)
    check_laps_and_credential_guard()
    print("")

    print_separator()
    write_color("\nClipboard content:\n", Colors.YELLOW)
    get_clipboard_content()

    print_separator()
    write_color("\nExtracting command history:\n", Colors.YELLOW)
    get_recently_run_commands()

    print_separator()
    write_color("\nReading WiFi passwords:\n", Colors.YELLOW)
    get_wifi_passwords()

    print_separator()
    write_color("\nSMB Shares:\n", Colors.YELLOW)
    get_smb_shares()

    print_separator()
    write_color("\nSMB Share Permissions:\n", Colors.YELLOW)
    get_smb_share_permissions()
    
    print_separator()


if __name__ == '__main__':
    main()
