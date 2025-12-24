import sqlite3
from tabulate import tabulate # pip install tabulate 可让输出像表格一样整齐

def search_ip_location(target_ip):
    conn = sqlite3.connect('network_tools.db')
    cursor = conn.cursor()

    # 优化后的 SQL
    query = """
    SELECT 
        a.ip_address, a.mac_address, m.switch_ip, s.brand, m.port, m.vlan, m.last_seen
    FROM arp_cache a
    JOIN mac_table m ON a.mac_address = m.mac_address
    JOIN switchs s ON m.switch_ip = s.ip
    WHERE a.ip_address = ?
      -- 排除 H3C 和 Cisco 常见的聚合口、上联口命名
      AND m.port NOT LIKE 'BAGG%'
      AND m.port NOT LIKE 'Bridge-Aggregation%'
      AND m.port NOT LIKE 'Po%'  -- 排除 Port-channel
      AND m.port NOT LIKE 'Vlan-interface%'
      AND m.port NOT LIKE 'NULL%'
    ORDER BY m.last_seen DESC
    """
    
    cursor.execute(query, (target_ip,))
    results = cursor.fetchall()
    conn.close()
    return results

def main():
    print("="*60)
    print("         IP 物理位置快速定位工具 (基于本地数据库)")
    print("="*60)
    
    ip = input("\n请输入要查询的 IP 地址: ").strip()
    
    if not ip:
        print("错误：IP 不能为空")
        return

    results = search_ip_location(ip)

    if results:
        # 使用 tabulate 格式化输出
        headers = ["IP", "MAC", "接入交换机", "品牌", "物理端口", "VLAN", "最后同步时间"]
        print("\n[查询成功] 定位信息如下：")
        print(tabulate(results, headers=headers, tablefmt="grid"))
        
        # 逻辑判断：如果查到了 MAC 但没查到端口（即 m 表关联为空）
        for res in results:
            if res[2] is None:
                print("\n[提示] 该 IP 在核心有 ARP 记录，但接入交换机数据库中未匹配到其 MAC。")
                print("可能原因：1. 接入交换机扫描不全；2. 该设备连接在未被扫描的设备上。")
    else:
        print(f"\n[!] 数据库中未找到 IP {ip} 的任何记录。")
        print("建议：1. 检查 IP 是否输入正确；2. 运行 arp_scanner.py 和 scanner.py 更新数据。")

if __name__ == "__main__":
    main()