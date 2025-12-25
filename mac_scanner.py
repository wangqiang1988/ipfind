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
    
    # 1. 自动识别设备类型
    if brand.lower() == 'cisco':
        device_type = 'cisco_ios_telnet' if protocol.lower() == 'telnet' else 'cisco_ios'
        cmd = "show mac address-table"
    else:
        device_type = 'hp_comware_telnet' if protocol.lower() == 'telnet' else 'hp_comware'
        cmd = "display mac-address"
    
    device = {
        'device_type': device_type,
        'ip': ip,
        'username': user,
        'password': pwd,
        'timeout': 120,
    }

    raw_results = []
    try:
        with ConnectHandler(**device) as ssh:
            # --- 核心：流式翻页处理 ---
            # 使用 timing 模式发送初始命令
            output = ssh.send_command_timing(cmd)
            full_output = output
            
            max_pages = 200 # 针对 800 条以上的数据，增加翻页次数上限
            for _ in range(max_pages):
                # 兼容思科的 --More-- 和 H3C 的 ---- More ----
                if "More" in output:
                    # 发送空格翻页
                    output = ssh.send_command_timing(" ")
                    full_output += output
                # 检测到命令提示符（> 或 #），说明抓取结束
                elif any(p in output for p in ['>', '#']):
                    break
                else:
                    # [修复点] 使用 read_channel() 代替 get_raw_output()
                    time.sleep(1)
                    output = ssh.read_channel() 
                    full_output += output
                    if not output: break

            # --- 2. 差异化正则表达式 ---
            if brand.lower() == 'cisco':
                # 思科匹配：VLAN  MAC(点分)  Type  Port
                pattern = r"(\d+)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+\S+\s+(\S+)"
            else:
                # H3C 匹配：MAC(横杠)  VLAN  State  Port
                pattern = r"([0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4})\s+(\d+)\s+\S+\s+(\S+)"

            matches = re.findall(pattern, full_output)
            
            # --- 3. 结果解析与过滤 ---
            port_stats = {}
            temp_data = []
            for m in matches:
                if brand.lower() == 'cisco':
                    v_vlan, v_mac, v_port = m
                else:
                    v_mac, v_vlan, v_port = m
                
                fmt_mac = "".join(filter(str.isalnum, v_mac)).upper()
                temp_data.append({'mac': fmt_mac, 'port': v_port, 'vlan': v_vlan})
                port_stats[v_port] = port_stats.get(v_port, 0) + 1

            for item in temp_data:
                p_name = item['port'].upper()
                # 过滤常见非终端口
                if any(x in p_name for x in ['PO', 'BAGG', 'NULL', 'VLAN', 'CPU', 'RMI']):
                    continue
                # 过滤带机量过大的上联口
                if port_stats[item['port']] > 100:
                    continue
                raw_results.append((item['mac'], ip, item['port'], item['vlan']))

        return ip, raw_results, True
    except Exception as e:
        return ip, f"Error: {str(e)}", False
        
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