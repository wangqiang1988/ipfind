import sqlite3
import os

def init_network_db(db_name='network_tools.db'):
    """
    初始化 SQLite 数据库及相关表结构
    """
    # 如果数据库文件已存在，可以选择删除重来或保留
    # if os.path.exists(db_name):
    #     os.remove(db_name)

    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # 1. 创建交换机资产表
    # 用于存放你要扫描的所有交换机信息
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS switchs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL UNIQUE,
        brand TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'access',
        last_scan TIMESTAMP
    )
''')

    # 2. 创建MAC地址记录表
    # 核心查询表：通过 MAC 找 交换机 + 端口
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mac_table (
            mac_address TEXT NOT NULL,        -- 统一格式后的MAC (如 00E0FC112233)
            switch_ip TEXT NOT NULL,          -- 所属交换机IP
            port TEXT NOT NULL,               -- 端口名称 (如 GigabitEthernet1/0/1)
            vlan TEXT,                        -- VLAN ID
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (mac_address, switch_ip), -- 联合主键，防止单台设备在多个交换机上重复（除非漂移）
            FOREIGN KEY (switch_ip) REFERENCES switches(ip)
        )
    ''')

    # 3. 创建ARP映射表 (可选)
    # 用于通过 IP 快速找到 MAC，减少对核心交换机的实时依赖
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS arp_cache (
            ip_address TEXT PRIMARY KEY,      -- IP地址
            mac_address TEXT NOT NULL,        -- 对应的MAC
            vlan TEXT,                        -- 所在的VLAN
            last_update TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 创建索引以提高查询速度
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_mac ON mac_table (mac_address)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip ON arp_cache (ip_address)')

    conn.commit()
    print(f"数据库 {db_name} 初始化成功！")
    conn.close()

if __name__ == "__main__":
    init_network_db()