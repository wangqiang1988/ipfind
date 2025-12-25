import sqlite3
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from netmiko import ConnectHandler
import paramiko 

# 全局忽略 SSH 证书确认（针对 SSH 协议生效）
paramiko.SSHClient().set_missing_host_key_policy(paramiko.AutoAddPolicy())

# --- 辅助函数：统一MAC格式 ---
def format_mac(raw_mac):
    if not raw_mac: return None
    return "".join(filter(str.isalnum, raw_mac)).upper()

# --- 数据库操作：获取核心交换机列表（增加 protocol 字段） ---
def get_core_switches():
    conn = sqlite3.connect('network_tools.db')
    cursor = conn.cursor()
    # 核心修改：读取 protocol 字段
    cursor.execute("SELECT ip, brand, username, password, protocol FROM switchs WHERE role='core'")
    cores = cursor.fetchall()
    conn.close()
    return cores

# --- 数据库操作：批量更新ARP缓存 ---
def update_arp_db(arp_records):
    if not arp_records:
        return
    conn = sqlite3.connect('network_tools.db', timeout=30)
    conn.execute("PRAGMA journal_mode=WAL;") # 开启WAL模式提高写入效率
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    data_to_insert = [
        (r['ip'], r['mac'], r['vlan'], now)
        for r in arp_records
    ]
    
    try:
        cursor.executemany('''
            REPLACE INTO arp_cache (ip_address, mac_address, vlan, last_update)
            VALUES (?, ?, ?, ?)
        ''', data_to_insert)
        conn.commit()
    except sqlite3.Error as e:
        print(f"[-] 数据库写入失败: {e}")
    finally:
        conn.close()

# --- 核心逻辑：单台设备采集函数 ---
def scan_core_worker(core_info):
    ip, brand, username, password, protocol = core_info
    
    # 动态确定 Netmiko 的 device_type
    base_type = 'hp_comware' if brand.lower() == 'h3c' else 'cisco_ios'
    # 如果协议是 telnet，则添加后缀 _telnet
    device_type = f"{base_type}_telnet" if protocol.lower() == 'telnet' else base_type
    
    device = {
        'device_type': device_type,
        'ip': ip,
        'username': username,
        'password': password,
        'timeout': 20,              # 稍微拉长超时
        'global_delay_factor': 2,    # 增加延迟因子以适配 Telnet 响应
    }

    # 如果是 SSH 模式，添加兼容性参数
    if protocol.lower() == 'ssh':
        device['ssh_strict'] = False 

    arp_list = []
    print(f"[*] [线程启动] 正在通过 {protocol.upper()} 连接核心: {ip} ({brand})...")
    
    try:
        with ConnectHandler(**device) as conn:
            # 兼容性处理：某些 Telnet 登录后需要一个回车激活
            if protocol.lower() == 'telnet':
                conn.send_command("\n", expect_string=r'[>#]')

            # 执行命令
            cmd = "display arp" if brand.lower() == 'h3c' else "show ip arp"
            output = conn.send_command(cmd)
            
            # 正则匹配
            if brand.lower() == 'h3c':
                pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4})\s+(\d+)"
            else:
                pattern = r"Internet\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+\w+\s+(?:Vlan|)(\d+)"

            matches = re.findall(pattern, output)
            
            for match in matches:
                ip_addr, raw_mac, vlan = match
                arp_list.append({
                    'ip': ip_addr,
                    'mac': format_mac(raw_mac),
                    'vlan': vlan
                })
        
        print(f"[+] [采集成功] {ip} ({protocol.upper()}) 解析到 {len(arp_list)} 条记录")
        return arp_list

    except Exception as e:
        print(f"[!] [采集失败] {ip} ({protocol.upper()}): {e}")
        return []

# --- 主函数 ---
def main():
    start_time = datetime.now()
    print(f"--- ARP 混合协议采集开始: {start_time.strftime('%H:%M:%S')} ---")
    
    cores = get_core_switches()
    if not cores:
        print("[-] 数据库中未找到 role='core' 的设备。")
        return

    all_arp_records = []
    # 使用 20 线程并发
    with ThreadPoolExecutor(max_workers=20) as executor:
        # 使用 as_completed 提高响应速度
        future_to_core = {executor.submit(scan_core_worker, core): core[0] for core in cores}
        
        for future in as_completed(future_to_core):
            res = future.result()
            if res:
                all_arp_records.extend(res)

    print(f"[*] 正在汇总入库 {len(all_arp_records)} 条记录...")
    update_arp_db(all_arp_records)
    
    duration = (datetime.now() - start_time).seconds
    print(f"--- 任务结束，耗时: {duration}秒 ---")

if __name__ == "__main__":
    main()