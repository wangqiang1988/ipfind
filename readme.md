# 收集核心、接入交换机arp、mac入库，查询ip所在接入交换机
方便查找ip地址所在接入交换机端口

# 使用方法
1.如config_env_example.py中的格式填写交换机的信息：模板、用户名、密码、核心交换机表、接入交换机表
2.生成数据库文件,数据库使用sqlite
```bash
python init_db.py
```
3.收集arp表，建议计划任务根据自己需要生成arp表时间，根据办公环境或生产环境，选择合适的执行入库周期
```bash
python arp_scanner.py
```
4.收集mac地址表，同样选择合适的周期进行入库
```bash
python mac_scanner.py
```
5.查询ip
```bash
python locator.py
```


