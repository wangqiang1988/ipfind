import sqlite3
import config_env

def batch_import():
    conn = sqlite3.connect('network_tools.db')
    cursor = conn.cursor()

    all_data = []
    
    # 辅助逻辑：处理不确定长度的配置元组
    def parse_switch_config(sw_list, role):
        parsed = []
        for sw in sw_list:
            # 假设 sw 原本是 (ip, brand, user, pwd, branch_name)
            # 我们需要适配成数据库字段: (ip, brand, username, password, role, protocol)
            
            ip = sw[0]
            brand = sw[1]
            user = sw[2]
            pwd = sw[3]
            
            # 协议判断逻辑：
            # 如果你在 config_env 里定义了第 6 个元素且它是 'telnet'
            if len(sw) >= 6 and sw[5].lower() == 'telnet':
                protocol = 'telnet'
            else:
                protocol = 'ssh'
            
            parsed.append((ip, brand, user, pwd, role, protocol))
        return parsed

    # 1. 处理核心列表
    all_data.extend(parse_switch_config(config_env.core_switchs, 'core'))

    # 2. 处理接入列表
    all_data.extend(parse_switch_config(config_env.access_switchs, 'access'))

    # 核心修改：增加 protocol 字段的写入
    cursor.executemany('''
        REPLACE INTO switchs (ip, brand, username, password, role, protocol) 
        VALUES (?, ?, ?, ?, ?, ?)
    ''', all_data)
    
    conn.commit()
    conn.close()
    print(f"✅ 成功导入/更新 {len(all_data)} 台设备资产（已同步协议字段）。")

if __name__ == "__main__":
    batch_import()