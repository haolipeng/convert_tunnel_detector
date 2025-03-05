package main

import (
	"fmt"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func Test_exprReplacement(t *testing.T) {
	var str = `"Hello world! I'm " + name + "."`
	env, err := cel.NewEnv(cel.Variable("name", cel.StringType)) //参数类型绑定
	if err != nil {
		t.Fatal(err)
	}

	ast, iss := env.Compile(str)
	if iss.Err() != nil {
		t.Fatal(iss.Err())
	}

	program, err := env.Program(ast)
	if err != nil {
		t.Fatal(err)
	}

	//初始化 name 变量的值
	values := map[string]interface{}{"name": "haolipeng"}
	//将值传递给程序，计算表达式的值
	out, detail, err := program.Eval(values)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(detail)
	fmt.Println(out)
}

func Test_LogicExpr(t *testing.T) {
	var str = `100 + 200 > 300`
	env, err := cel.NewEnv()
	if err != nil {
		t.Fatal(err)
	}

	ast, iss := env.Compile(str)
	if iss.Err() != nil {
		t.Fatal(iss.Err())
	}

	program, err := env.Program(ast)
	if err != nil {
		t.Fatal(err)
	}

	//初始化 name 变量的值
	values := map[string]interface{}{}
	//将值传递给程序，计算表达式的值
	out, detail, err := program.Eval(values)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(detail)
	fmt.Println(out)
}

func Test_LogicAndOrOperater(t *testing.T) {
	// 创建 CEL 环境
	env, err := cel.NewEnv(
		cel.Variable("age", cel.IntType),
		cel.Variable("vip", cel.BoolType),
	)
	if !assert.NoError(t, err, "环境创建失败") {
		t.FailNow()
	}

	// 定义测试用例
	tests := []struct {
		name     string         //测试用例的名称
		expr     string         //表达式
		vars     map[string]any //变量的值
		expected bool           //期望值
	}{
		{
			name:     "AND_TrueCase",
			expr:     "age >= 18 && vip == true",
			vars:     map[string]any{"age": 20, "vip": true},
			expected: true,
		},
		{
			name:     "AND_FalseCase1",
			expr:     "age >= 18 && vip == true",
			vars:     map[string]any{"age": 20, "vip": false},
			expected: false,
		},
		{
			name:     "AND_FalseCase2",
			expr:     "age >= 18 && vip == true",
			vars:     map[string]any{"age": 15, "vip": true},
			expected: false,
		},
		{
			name:     "OR_TrueCase1",
			expr:     "age < 18 || vip == false",
			vars:     map[string]any{"age": 15, "vip": true},
			expected: true,
		},
		{
			name:     "OR_TrueCase2",
			expr:     "age < 18 || vip == false",
			vars:     map[string]any{"age": 20, "vip": false},
			expected: true,
		},
		{
			name:     "OR_FalseCase",
			expr:     "age < 18 || vip == false",
			vars:     map[string]any{"age": 20, "vip": true},
			expected: false,
		},
	}

	// 遍历执行测试用例
	for _, tt := range tests {
		//使用 t.Run() 为每个用例创建独立子测试,单独运行某个测试：go test -run Test_LogicAndOrOperater/AND_TrueCase
		t.Run(tt.name, func(t *testing.T) {
			// 解析和类型检查
			ast, iss := env.Parse(tt.expr)
			if !assert.Nil(t, iss.Err(), "表达式解析失败") {
				t.FailNow()
			}

			checked, iss := env.Check(ast)
			if !assert.Nil(t, iss.Err(), "类型检查失败") {
				t.FailNow()
			}

			// 编译表达式
			prg, err := env.Program(checked)
			if !assert.NoError(t, err, "编译失败") {
				t.FailNow()
			}

			// 执行评估
			result, _, err := prg.Eval(tt.vars)
			if !assert.NoError(t, err, "执行失败") {
				t.FailNow()
			}

			// 验证结果,通过类型断言确保返回值为 bool 类型
			val, ok := result.Value().(bool)
			if !assert.True(t, ok, "结果类型错误") {
				t.FailNow()
			}
			assert.Equal(t, tt.expected, val, "结果不符合预期")
		})
	}
}

// 自定义函数示例：字符串转大写
func upperString(str string) string {
	return strings.ToUpper(str)
}

func Test_CustomFunction(t *testing.T) {
	env, err := cel.NewEnv(
		cel.Function("upper",
			cel.Overload("upper_string",
				[]*cel.Type{cel.StringType},
				cel.StringType,
				cel.UnaryBinding(func(str ref.Val) ref.Val {
					s, ok := str.Value().(string)
					if !ok {
						return types.NewErr("参数必须为字符串")
					}
					return types.String(upperString(s))
				}),
			),
		),
	)
	if !assert.NoError(t, err, "环境创建失败") {
		t.FailNow()
	}

	tests := []struct {
		name     string
		expr     string
		expected interface{}
		isError  bool
	}{
		{
			name:     "正常调用-字符串转大写",
			expr:     `upper("hello")`,
			expected: "HELLO",
		},
		{
			name:     "空字符串处理",
			expr:     `upper("")`,
			expected: "",
		},
		{
			name:     "错误参数类型",
			expr:     `upper(123)`,
			isError:  true,
			expected: "no such overload: upper(int)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, iss := env.Parse(tt.expr)
			if iss != nil && iss.Err() != nil {
				if tt.isError {
					assert.Contains(t, iss.Err().Error(), tt.expected.(string))
					return
				}
				assert.NoError(t, iss.Err(), "表达式解析失败")
				return
			}

			checked, iss := env.Check(ast)
			if iss != nil && iss.Err() != nil {
				if tt.isError {
					assert.Contains(t, iss.Err().Error(), tt.expected.(string))
					return
				}
				assert.NoError(t, iss.Err(), "类型检查失败")
				return
			}

			prg, err := env.Program(checked)
			if !assert.NoError(t, err, "编译失败") {
				return
			}

			result, _, err := prg.Eval(cel.NoVars())
			if tt.isError {
				if assert.Error(t, err) {
					assert.Contains(t, err.Error(), tt.expected.(string))
				}
				return
			}
			if !assert.NoError(t, err, "执行失败") {
				return
			}

			val := result.Value()
			assert.Equal(t, tt.expected, val)
		})
	}
}
