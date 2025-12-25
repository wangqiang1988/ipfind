import sqlite3
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from netmiko import ConnectHandler
import paramiko 

paramiko.SSHClient().set_missing_host_key_policy(paramiko.AutoAddPolicy())
# --- 辅助函数：统一MAC格式 ---
def format_mac(raw_mac):
    if not raw_mac: return None
    # 去除横杠、点、冒号，并转为大写
    return "".join(filter(str.isalnum, raw_mac)).upper()

# --- 数据库操作：获取核心交换机列表 ---
def get_core_switches():
    conn = sqlite3.connect('network_tools.db')
    cursor = conn.cursor()
    # 从 switchs 表中筛选角色为 core 的设备
    cursor.execute("SELECT ip, brand, username, password FROM switchs WHERE role='core'")
    cores = cursor.fetchall()
    conn.close()
    return cores

# --- 数据库操作：批量更新ARP缓存 ---
def update_arp_db(arp_records):
    if not arp_records:
        return
    
    conn = sqlite3.connect('network_tools.db')
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 构造入库数据 (ip, mac, vlan, time)
    data_to_insert = [
        (r['ip'], r['mac'], r['vlan'], now)
        for r in arp_records
    ]
    
    try:
        # 使用 REPLACE INTO 保证 IP 始终指向最新的 MAC
        cursor.executemany('''
            REPLACE INTO arp_cache (ip_address, mac_address, vlan, last_update)
            VALUES (?, ?, ?, ?)
        ''', data_to_insert)
        conn.commit()
    except sqlite3.Error as e:
        print(f"[-] 数据库写入失败: {e}")
    finally:
        conn.close()

# --- 核心逻辑：单台设备采集函数 (供线程池调用) ---
def scan_core_worker(core_info):
    ip, brand, username, password = core_info
    
    # 根据品牌选择 Netmiko 设备类型
    device_type = 'hp_comware' if brand.lower() == 'h3c' else 'cisco_ios'
    
    device = {
        'device_type': device_type,
        'ip': ip,
        'username': username,
        'password': password,
        'timeout': 15,  # 核心设备可能较慢，超时设长一点
    }

    arp_list = []
    print(f"[*] [线程启动] 正在连接核心: {ip} ({brand})...")
    
    try:
        with ConnectHandler(**device) as ssh:
            if brand.lower() == 'h3c':
                # H3C 命令: display arp
                output = ssh.send_command("display arp")
                # 正则匹配示例: 192.168.1.100  00e0-fc11-2233  10  VLAN10  D  0
                # 匹配：IP, MAC, VLAN
                pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4})\s+(\d+)"
            else:
                # Cisco 命令: show ip arp
                output = ssh.send_command("show ip arp")
                # 正则匹配示例: Internet  192.168.1.100  15  0011.2233.4455  ARPA  Vlan10
                pattern = r"Internet\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+\w+\s+(?:Vlan|)(\d+)"

            matches = re.findall(pattern, output)
            
            for match in matches:
                ip_addr, raw_mac, vlan = match
                arp_list.append({
                    'ip': ip_addr,
                    'mac': format_mac(raw_mac),
                    'vlan': vlan
                })
        
        print(f"[+] [采集成功] {ip} 解析到 {len(arp_list)} 条 ARP 记录")
        return arp_list

    except Exception as e:
        print(f"[!] [采集失败] {ip}: {e}")
        return []

# --- 主函数 ---
def main():
    start_time = datetime.now()
    print(f"--- ARP 采集任务开始于: {start_time.strftime('%H:%M:%S')} ---")
    
    # 1. 获取核心交换机列表
    cores = get_core_switches()
    if not cores:
        print("[-] 数据库中未找到 role='core' 的设备，请检查 switchs 表。")
        return

    # 2. 使用线程池并行采集
    # max_workers 建议根据核心数量调整，通常 5-10 比较稳健
    all_arp_records = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        # 将任务分发给多个线程
        future_to_core = {executor.submit(scan_core_worker, core): core for core in cores}
        
        for future in future_to_core:
            result = future.result()
            if result:
                all_arp_records.extend(result)

    # 3. 汇总数据入库
    print(f"[*] 正在将总计 {len(all_arp_records)} 条记录存入数据库...")
    update_arp_db(all_arp_records)
    
    end_time = datetime.now()
    duration = (end_time - start_time).seconds
    print(f"--- ARP 任务结束，耗时: {duration}秒，总记录数: {len(all_arp_records)} ---")

if __name__ == "__main__":
    main()