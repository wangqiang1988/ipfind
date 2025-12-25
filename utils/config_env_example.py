model1 = "cisco"
model2 = "h3c"
username = ""
password = ""

core_switchs = [
('10.1.1.1', model1, username, password, 'location1'),
('10.2.1.1', model2, username, password, 'location2', 'telnet'),

]

access_switchs = [
('10.1.1.11', model1, username, password),
('10.2.1.11', model2, username, password, 'location2', 'telnet'),

]
