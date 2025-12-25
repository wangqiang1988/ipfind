import sqlite3
import re
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from netmiko import ConnectHandler
import paramiko 

# 全局忽略 SSH 证书确认
paramiko.SSHClient().set_missing_host_key_policy(paramiko.AutoAddPolicy())

# --- 1. 配置与工具函数 ---
MAX_THREADS = 25  # 500台规模建议设为 20-30
COMMAND_TIMEOUT = 20

def format_mac(raw_mac):
    if not raw_mac: return None
    return "".join(filter(str.isalnum, raw_mac)).upper()

def get_access_switches():
    conn = sqlite3.connect('network_tools.db')
    cursor = conn.cursor()
    # 增加 protocol 字段读取
    cursor.execute("SELECT ip, brand, username, password, protocol FROM switchs WHERE role='access'")
    switches = cursor.fetchall()
    conn.close()
    return switches

# --- 2. 增强型级联口识别 ---
def get_uplink_ports(ssh, brand, protocol):
    """识别级联口及聚合组，返回黑名单集合"""
    uplinks = set()
    try:
        # LLDP 基础识别
        lldp_cmd = "display lldp neighbor-information list" if brand.lower() == 'h3c' else "show lldp neighbors"
        output = ssh.send_command(lldp_cmd)
        for line in output.splitlines():
            # 正则匹配端口名（支持H3C/Cisco多种格式）
            match = re.search(r'^([a-zA-Z0-9/:-]+)', line.strip())
            if match:
                port = match.group(1)
                if port.upper() not in ['SYSTEMNAME', 'LOCAL', 'CHASSIS', 'PORTID', '----']:
                    uplinks.add(port)
        
        # H3C 额外识别聚合口
        if brand.lower() == 'h3c':
            agg_output = ssh.send_command("display link-aggregation summary")
            agg_ports = re.findall(r'(BAGG\d+|Bridge-Aggregation\d+)', agg_output)
            for p in agg_ports: uplinks.add(p)
            
    except: pass 
    return uplinks

# --- 3. 单台扫描任务 (混合协议版) ---
def task_scan_switch(sw_info):
    ip, brand, user, pwd, protocol = sw_info
    
    base_type = 'hp_comware' if brand.lower() == 'h3c' else 'cisco_ios'
    device_type = f"{base_type}_telnet" if protocol.lower() == 'telnet' else base_type
    
    device = {
        'device_type': device_type,
        'ip': ip,
        'username': user,
        'password': pwd,
        'timeout': COMMAND_TIMEOUT,
        'global_delay_factor': 2,
    }
    
    if protocol.lower() == 'ssh':
        device['ssh_strict'] = False

    raw_results = []
    try:
        # 错峰
        time.sleep(random.uniform(0, 3))
        
        with ConnectHandler(**device) as ssh:
            # 1. 执行命令获取原始 MAC 表
            if brand.lower() == 'h3c':
                output = ssh.send_command("display mac-address dynamic")
                pattern = r"([0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4})\s+(\d+)\s+\w+\s+([\w\/\-\.]+)"
            else:
                output = ssh.send_command("show mac address-table dynamic")
                pattern = r"(\d+)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+\w+\s+([\w\/\-\.]+)"

            matches = re.findall(pattern, output)
            
            # 2. 第一次遍历：统计每个端口下的 MAC 数量
            port_stats = {}
            temp_data = []
            for m in matches:
                # 兼容不同品牌字段位置
                v_mac, v_vlan, v_port = (m[0], m[1], m[2]) if brand.lower() == 'h3c' else (m[1], m[0], m[2])
                
                temp_data.append({'mac': format_mac(v_mac), 'port': v_port, 'vlan': v_vlan})
                port_stats[v_port] = port_stats.get(v_port, 0) + 1

            # 3. 第二次遍历：根据逻辑进行过滤
            for item in temp_data:
                p_name = item['port']
                p_upper = p_name.upper()

                # --- 过滤逻辑开始 ---
                # A. 过滤掉聚合口 (这些绝对是级联口)
                if any(x in p_upper for x in ['BAGG', 'PORT-CHANNEL', 'PO', 'BRIDGE-AGG']):
                    continue  # 此处 continue 现在已在 for 循环内
                
                # B. 过滤掉非物理端口 (如 VLAN 接口、NULL 接口等)
                if any(x in p_upper for x in ['VLAN', 'NULL', 'RTK']):
                    continue

                # C. [可选建议] 
                # 即使有 HUB，如果一个端口 MAC 超过 100 个，那 99% 还是上联口
                # 如果不想过滤 HUB，可以把阈值设大（比如 100）
                if port_stats[p_name] > 100:
                    continue

                # 符合条件的记录才加入结果集
                raw_results.append((item['mac'], ip, p_name, item['vlan']))
                # --- 过滤逻辑结束 ---

        return ip, raw_results, True
    except Exception as e:
        return ip, str(e), False
# --- 4. 数据库批量写入 (WAL 增强版) ---
def save_to_db(all_records):
    if not all_records: return
    conn = sqlite3.connect('network_tools.db', timeout=30)
    # 开启 WAL 模式提高并发性能
    conn.execute("PRAGMA journal_mode=WAL;")
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
    print(f"[*] MAC 混合协议扫描开始: {start_time.strftime('%H:%M:%S')}")
    
    switches = get_access_switches()
    if not switches:
        print("[-] 未找到接入交换机资产。")
        return

    # 扫描前清空旧数据，防止陈旧记录干扰 Locator
    conn = sqlite3.connect('network_tools.db')
    conn.execute("DELETE FROM mac_table")
    conn.commit()
    conn.close()

    all_mac_records = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_sw = {executor.submit(task_scan_switch, sw): sw[0] for sw in switches}
        
        for future in as_completed(future_to_sw):
            sw_ip = future_to_sw[future]
            try:
                ip, data, success = future.result()
                if success:
                    all_mac_records.extend(data)
                    print(f"[+] {ip} 成功 (抓取终端: {len(data)})")
                else:
                    print(f"[!] {ip} 失败: {data}")
            except Exception as e:
                print(f"[!] {sw_ip} 崩溃: {e}")

    print(f"[*] 写入数据库 (总计: {len(all_mac_records)})...")
    save_to_db(all_mac_records)
    
    duration = (datetime.now() - start_time).seconds
    print(f"--- 扫描结束 | 耗时: {duration}s | 有效终端: {len(all_mac_records)} ---")

if __name__ == "__main__":
    main()