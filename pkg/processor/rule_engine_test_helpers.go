package processor

import (
	"github.com/google/cel-go/cel"
	"github.com/haolipeng/convert_tunnel_detector/pkg/ruleEngine"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
)

// TestCompileRule 是 compileRule 函数的测试包装器
func TestCompileRule(env *cel.Env, rule *ruleEngine.Rule, ruleProtocol string) (cel.Program, error) {
	return compileRuleToProgram(env, rule, ruleProtocol)
}

// CreateTestRuleEngine 创建一个用于测试的规则引擎
func CreateTestRuleEngine() (*RuleEngine, error) {
	env, err := cel.NewEnv()
	if err != nil {
		return nil, err
	}

	return &RuleEngine{
		Env: env,
	}, nil
}

// TestEvaluateRule 是 evaluateRule 方法的测试包装器
func (r *RuleEngine) TestEvaluateRule(program cel.Program, vars map[string]interface{}) (bool, error) {
	return r.evaluateRule(program, vars)
}

// TestBuildEvalVars 是 buildEvalVars 函数的测试包装器
func TestBuildEvalVars(packet *types.Packet) map[string]interface{} {
	return buildEvalVars(packet)
}
