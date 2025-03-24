# 获取所有规则
curl -X GET http://localhost:8080/api/v1/ruleEngine/configs | jq .

# 按协议过滤规则
curl -X GET http://localhost:8080/api/v1/ruleEngine/configs?protocol=ospf | jq .

# 创建规则
curl -X POST http://localhost:8080/api/v1/ruleEngine/configs/ospf_test_rule \
  -H "Content-Type: application/json" \
  -d @ospf_blacklist_rule.json

# 获取特定规则
curl -X GET http://localhost:8080/api/v1/ruleEngine/configs/ospf_test_rule | jq .

# 更新规则
curl -X PUT http://localhost:8080/api/v1/ruleEngine/configs/ospf_test_rule \
  -H "Content-Type: application/json" \
  -d @update_ospf_rule.json

# 启动规则
curl -X POST http://localhost:8080/api/v1/ruleEngine/configs/ospf_test_rule/start

# 停止规则
curl -X POST http://localhost:8080/api/v1/ruleEngine/configs/ospf_test_rule/stop

# 删除规则
curl -X POST http://localhost:8080/api/v1/ruleEngine/configs/ospf_test_rule/delete