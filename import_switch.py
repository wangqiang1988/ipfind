import sqlite3
import config_env

def batch_import():
    conn = sqlite3.connect('network_tools.db')
    cursor = conn.cursor()

    all_data = []
    
    # 1. 处理核心列表
    for core in config_env.core_switchs:
        # core 结构: (ip, brand, user, pwd, branch_name)
        # 我们存入数据库: (ip, brand, user, pwd, 'core')
        all_data.append((core[0], core[1], core[2], core[3], 'core'))

    # 2. 处理接入列表
    for acc in config_env.access_switchs:
        all_data.append((acc[0], acc[1], acc[2], acc[3], 'access'))

    cursor.executemany('''
        REPLACE INTO switchs (ip, brand, username, password, role) 
        VALUES (?, ?, ?, ?, ?)
    ''', all_data)
    
    conn.commit()
    conn.close()
    print(f"成功导入 {len(all_data)} 台设备资产。")

if __name__ == "__main__":
    batch_import()