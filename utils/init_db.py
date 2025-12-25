import sqlite3
import os

def init_network_db(db_name='network_tools.db'):
    """
    初始化 SQLite 数据库及相关表结构 (适配 SSH/Telnet 混合模式)
    """
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # --- 1. 修改交换机资产表 ---
    # 核心变动：增加了 protocol 字段
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS switchs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL UNIQUE,
        brand TEXT NOT NULL,          -- H3C, Cisco 等
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'access',   -- core (核心), access (接入)
        protocol TEXT DEFAULT 'ssh',  -- ssh, telnet (关键修改)
        last_scan TIMESTAMP
    )
    ''')

    # --- 2. 修改 MAC 地址记录表 ---
    # 核心变动：主键改为 (mac_address, switch_ip, port) 
    # 理由：同一个MAC在级联口环境下可能出现在多个交换机，必须记录所有位置供后续逻辑过滤
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mac_table (
            mac_address TEXT NOT NULL,
            switch_ip TEXT NOT NULL,
            port TEXT NOT NULL,
            vlan TEXT,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (mac_address, switch_ip, port)
        )
    ''')

    # --- 3. ARP 映射表 ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS arp_cache (
            ip_address TEXT PRIMARY KEY,
            mac_address TEXT NOT NULL,
            vlan TEXT,
            last_update TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # --- 4. 索引优化 (针对 500 台设备规模) ---
    # 扫描时经常按角色查询设备
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_sw_role ON switchs (role)')
    # 查询位置时核心是 MAC 字段
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_mac_search ON mac_table (mac_address)')
    # ARP 映射通过 MAC 反查 IP 也很快
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_arp_mac ON arp_cache (mac_address)')

    # --- 5. 性能预设 ---
    # 开启 WAL 模式，确保多线程写入时不锁库
    cursor.execute("PRAGMA journal_mode=WAL;")

    conn.commit()
    print(f"✅ 数据库 {db_name} 初始化/更新成功！")
    print(f"💡 记得在 switchs 表中将老旧设备的 protocol 字段设置为 'telnet'")
    conn.close()

if __name__ == "__main__":
    init_network_db()