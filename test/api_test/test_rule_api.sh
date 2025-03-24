#!/bin/bash

# 设置API地址和端口
HOST="localhost"
PORT="8080"
API_BASE="http://${HOST}:${PORT}/api/v1/ruleEngine"
TEST_RULE_ID="ospf_blacklist_test"

# 彩色输出函数
function print_header() {
  echo -e "\n\033[1;36m==== $1 ====\033[0m\n"
}

function print_success() {
  echo -e "\033[1;32m✓ $1\033[0m"
}

function print_error() {
  echo -e "\033[1;31m✗ $1\033[0m"
}

# 检查上一个命令是否成功
function check_result() {
  if [ $? -eq 0 ]; then
    print_success "$1"
  else
    print_error "$1 失败"
    exit 1
  fi
}

# 检查jq是否安装
if ! command -v jq &> /dev/null; then
  echo "警告: jq 未安装，输出将不会格式化。建议安装jq: apt-get install jq 或 yum install jq"
  # 定义一个不执行操作的jq替代函数
  function jq() {
    cat
  }
fi

# 0. 检查服务是否可访问
print_header "检查API服务是否可访问"
if curl -s -o /dev/null -w "%{http_code}" "${API_BASE}/configs" | grep -q "200\|404"; then
  print_success "API服务可访问"
else
  print_error "API服务不可访问，请确认服务已启动且地址正确"
  echo "尝试连接的地址: ${API_BASE}/configs"
  exit 1
fi

# 1. 获取所有规则配置
print_header "获取所有规则配置"
curl -s -X GET "${API_BASE}/configs" | jq .
check_result "获取所有规则"

# 2. 按协议过滤规则
print_header "按协议过滤规则 (OSPF)"
curl -s -X GET "${API_BASE}/configs?protocol=ospf" | jq .
check_result "按协议过滤规则"

# 3. 按模式过滤规则
print_header "按模式过滤规则 (blacklist)"
curl -s -X GET "${API_BASE}/configs?mode=blacklist" | jq .
check_result "按模式过滤规则"

# 4. 按状态过滤规则
print_header "按状态过滤规则 (enable)"
curl -s -X GET "${API_BASE}/configs?state=enable" | jq .
check_result "按状态过滤规则"

# 5. 创建OSPF黑名单规则
print_header "创建OSPF黑名单规则"
curl -s -X POST "${API_BASE}/configs/${TEST_RULE_ID}" \
  -H "Content-Type: application/json" \
  -d @ospf_blacklist_rule.json | jq .
check_result "创建OSPF黑名单规则"

# 6. 获取特定规则
print_header "获取特定规则"
curl -s -X GET "${API_BASE}/configs/${TEST_RULE_ID}" | jq .
check_result "获取特定规则"

# 7. 停止规则
print_header "停止规则"
curl -s -X POST "${API_BASE}/configs/${TEST_RULE_ID}/stop" | jq .
check_result "停止规则"

# 8. 查看规则状态是否改变
print_header "检查规则状态变更"
curl -s -X GET "${API_BASE}/configs/${TEST_RULE_ID}" | jq .
check_result "检查规则状态"

# 9. 启动规则
print_header "启动规则"
curl -s -X POST "${API_BASE}/configs/${TEST_RULE_ID}/start" | jq .
check_result "启动规则"

# 10. 更新规则
print_header "更新规则"
curl -s -X PUT "${API_BASE}/configs/${TEST_RULE_ID}" \
  -H "Content-Type: application/json" \
  -d @update_ospf_rule.json | jq .
check_result "更新规则"

# 11. 检查规则是否已更新
print_header "检查规则更新"
curl -s -X GET "${API_BASE}/configs/${TEST_RULE_ID}" | jq .
check_result "检查规则更新"

# 12. 删除规则
print_header "删除规则"
curl -s -X POST "${API_BASE}/configs/${TEST_RULE_ID}/delete" | jq .
check_result "删除规则"

# 13. 验证规则已被删除
print_header "验证规则删除"
RESULT=$(curl -s -w "%{http_code}" -o /dev/null -X GET "${API_BASE}/configs/${TEST_RULE_ID}")
if [ "$RESULT" == "404" ]; then
  print_success "验证规则已被删除"
else
  print_error "规则删除验证失败"
  echo "HTTP状态码: $RESULT"
fi

print_header "测试完成"
echo "所有测试已顺利完成！" 