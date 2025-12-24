import sqlite3
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from netmiko import ConnectHandler

# --- 1. 配置参数 ---
MAX_THREADS = 15  # 并发线程数，根据服务器性能可调至 10-30
COMMAND_TIMEOUT = 15

# --- 2. 辅助工具函数 ---
def format_mac(raw_mac):
    if not raw_mac: return None
    return "".join(filter(str.isalnum, raw_mac)).upper()

def get_access_switches():
    conn = sqlite3.connect('network_tools.db')
    cursor = conn.cursor()
    # 只抓取接入交换机
    cursor.execute("SELECT ip, brand, username, password FROM switchs WHERE role='access'")
    switches = cursor.fetchall()
    conn.close()
    return switches

def get_uplink_ports(ssh, brand):
    """
    核心优化：识别级联口（LLDP邻居口）
    返回一个集合，包含所有连接了其他交换机的端口
    """
    uplinks = set()
    try:
        if brand.lower() == 'h3c':
            output = ssh.send_command("display lldp neighbor-information list")
            # 匹配第一列的端口名，如 GE1/0/1 或 BAGG1
            lines = output.splitlines()
            for line in lines:
                match = re.search(r'^([a-zA-Z0-9/:-]+)\s+', line.strip())
                if match: uplinks.add(match.group(1))
        else:
            output = ssh.send_command("show lldp neighbors")
            # Cisco 简化匹配 Local Intf
            lines = output.splitlines()
            for line in lines:
                match = re.search(r'^([a-zA-Z0-9/:-]+)\s+', line.strip())
                if match: uplinks.add(match.group(1))
    except:
        pass # 如果不支持LLDP则跳过过滤
    return uplinks

# --- 3. 单台交换机扫描任务 ---
def task_scan_switch(sw_info):
    ip, brand, user, pwd = sw_info
    device_type = 'hp_comware' if brand.lower() == 'h3c' else 'cisco_ios'
    
    device = {
        'device_type': device_type,
        'ip': ip,
        'username': user,
        'password': pwd,
        'timeout': COMMAND_TIMEOUT,
    }

    results = []
    try:
        with ConnectHandler(**device) as ssh:
            # A. 先获取级联口黑名单
            uplinks = get_uplink_ports(ssh, brand)
            
            # B. 获取 MAC 地址表
            if brand.lower() == 'h3c':
                output = ssh.send_command("display mac-address dynamic")
                pattern = r"([0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4})\s+(\d+)\s+\w+\s+([\w\/\-\.]+)"
            else:
                output = ssh.send_command("show mac address-table dynamic")
                pattern = r"(\d+)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+\w+\s+([\w\/\-\.]+)"

            matches = re.findall(pattern, output)
            
            for match in matches:
                if brand.lower() == 'h3c':
                    mac, vlan, port = match
                else:
                    vlan, mac, port = match
                
                # 过滤逻辑：
                # 1. 过滤掉级联口 (LLDP 发现的邻居口)
                # 2. 过滤掉聚合口 (BAGG/Po/Port-channel)
                port_upper = port.upper()
                if port in uplinks: continue
                if any(x in port_upper for x in ['BAGG', 'PORT-CHANNEL', 'PO', 'BRIDGE-AGG']): continue
                
                results.append((format_mac(mac), ip, port, vlan))
                
        return ip, results, True
    except Exception as e:
        return ip, str(e), False

# --- 4. 数据库批量写入 ---
def save_to_db(all_records):
    if not all_records: return
    conn = sqlite3.connect('network_tools.db')
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 构造入库数据
    final_data = [ (r[0], r[1], r[2], r[3], now) for r in all_records ]
    
    try:
        cursor.executemany('''
            REPLACE INTO mac_table (mac_address, switch_ip, port, vlan, last_seen)
            VALUES (?, ?, ?, ?, ?)
        ''', final_data)
        conn.commit()
    finally:
        conn.close()

# --- 5. 主程序 ---
def main():
    start_time = datetime.now()
    print(f"[*] MAC 扫描任务开始: {start_time.strftime('%H:%M:%S')}")
    
    switches = get_access_switches()
    if not switches:
        print("[-] 没有找到接入交换机资产。")
        return

    total_mac_count = 0
    all_mac_records = []

    # 使用线程池并发执行
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_sw = {executor.submit(task_scan_switch, sw): sw[0] for sw in switches}
        
        for future in as_completed(future_to_sw):
            sw_ip = future_to_sw[future]
            try:
                ip, data, success = future.result()
                if success:
                    all_mac_records.extend(data)
                    print(f"[+] {ip} 扫描完成 (抓取到 {len(data)} 条有效终端记录)")
                else:
                    print(f"[!] {ip} 扫描失败: {data}")
            except Exception as e:
                print(f"[!] {sw_ip} 线程崩溃: {e}")

    # 批量入库
    print(f"[*] 正在写入数据库...")
    save_to_db(all_mac_records)
    
    duration = (datetime.now() - start_time).seconds
    print(f"--- 扫描结束 ---")
    print(f"总耗时: {duration} 秒")
    print(f"总计有效终端记录: {len(all_mac_records)} 条")

if __name__ == "__main__":
    main()