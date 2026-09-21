// OpenAPI 3.0 specification for the KingMoat console API, served at
// /openapi.json and rendered by the built-in Swagger UI (#/docs).
package api

import (
	"net/http"
)

func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	spec := map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       "KingMoat WAF Console API",
			"description": "KingMoat 下一代应用防火墙控制台 API。认证：POST /api/login 获取会话 Cookie，或 Basic（admin:<password>）。",
			"version":     s.opts.Version,
		},
		"servers": []map[string]string{{"url": "/"}},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"basicAuth":  map[string]any{"type": "http", "scheme": "basic"},
				"cookieAuth": map[string]any{"type": "apiKey", "in": "cookie", "name": "km_session"},
			},
		},
		"security": []map[string]any{{"cookieAuth": []any{}}, {"basicAuth": []any{}}},
		"paths": map[string]any{
			"/api/login":            postOp("登录", "用户名+密码(+TOTP) 换取会话 Cookie"),
			"/api/logout":           postOp("登出并吊销会话", nil),
			"/api/status":           getOp("运行状态", versionSchema()),
			"/api/config":           getOp("当前生效配置", objectSchema("revision", "config")),
			"/api/config/publish":   postOp("发布配置（热生效，校验失败保旧）", nil),
			"/api/revisions":               getOp("配置版本历史", nil),
			"/api/revisions/{id}/rollback": postOp("回滚到指定版本", nil),
			"/api/logs":                   getOp("攻击/事件日志（SQLite 全量检索）", nil),
			"/api/logs/storage":           getOp("日志存储态势", nil),
			"/api/stats":                  getOp("今日统计", nil),
			"/api/stats/geo":              getOp("攻击来源地域聚合", nil),
			"/api/stats/rules":            getOp("规则命中 TOP 统计（策略页统计卡）", nil),
			"/api/certificates":           getOp("站点证书清单", nil),
			"/api/certificates/upload":    postOp("上传证书（cert+key 或压缩包 zip/tar.gz，5 层，内容识别+公钥配对）", nil),
			"/api/certificates/uploads":   getOp("已上传证书库", nil),
			"/api/certificates/uploads/{name}": deleteOp("删除证书库条目（被站点/控制台引用时拒绝）"),
			"/api/policy/whitelist": postOp("一键加白 → 生成微引擎放行规则（站点+路径条件，action=allow 跳过全部检测；幂等，重复返回 unchanged）", nil),
			"/api/policy/exceptions": mergeOps(getOp("[deprecated] 误报加白例外列表（旧版，改用 /api/policy/whitelist）", nil), postOp("[deprecated] 新增加白例外（旧版，改用 /api/policy/whitelist）", nil)),
			"/api/policy/exceptions/{index}": deleteOp("[deprecated] 撤销加白例外（旧版）"),
			"/api/ipgroups":               getOp("IP 组订阅列表（含预览）", nil),
			"/api/ipgroups/{name}/refresh": postOp("手动刷新订阅组", nil),
			"/api/users": mergeOps(getOp("控制台用户列表（admin）", nil), postOp("新增用户（admin）", nil)),
			"/api/users/{username}": mergeOps(patchOp("改角色/密码/禁用/邮箱（admin）"), deleteOp("删除用户（admin，最后启用管理员受保护）")),
			"/api/users/{username}/reset-password": postOp("重置用户密码（admin，返回一次性临时密码，下次登录强制改密）", nil),
			"/api/console/tls":            mergeOps(getOp("管理控制台证书态势（自签名/库内绑定）", nil), postOp("切换管理控制台证书（库内条目，热生效）", nil)),
			"/api/assets/apis":            getOp("API 资产清单", nil),
			"/api/risks":                  getOp("风险列表", nil),
			"/api/risks/scan":             postOp("触发风险扫描", nil),
			"/api/ai/chat":                postOp("AI 助手对话（SSE 流式）", nil),
			"/metrics":                    getOp("Prometheus 指标", nil),
		},
	}
	writeJSON(w, http.StatusOK, spec)
}

func getOp(summary string, schema any) map[string]any {
	op := map[string]any{"get": map[string]any{"summary": summary, "responses": map[string]any{
		"200": map[string]any{"description": "OK"}}}}
	return op
}

func postOp(summary string, _ any) map[string]any {
	return map[string]any{"post": map[string]any{"summary": summary, "responses": map[string]any{
		"200": map[string]any{"description": "OK"},
		"400": map[string]any{"description": "校验失败"},
		"401": map[string]any{"description": "未认证"},
		"403": map[string]any{"description": "角色不足"},
	}}}
}

func patchOp(summary string) map[string]any {
	return map[string]any{"patch": map[string]any{"summary": summary, "responses": map[string]any{
		"200": map[string]any{"description": "OK"}}}}
}

func deleteOp(summary string) map[string]any {
	return map[string]any{"delete": map[string]any{"summary": summary, "responses": map[string]any{
		"200": map[string]any{"description": "OK"}}}}
}

func versionSchema() any {
	return map[string]any{"type": "object", "properties": map[string]any{
		"version": map[string]string{"type": "string"},
		"revision": map[string]string{"type": "integer"},
		"sites":   map[string]string{"type": "integer"},
	}}
}

func objectSchema(fields ...string) any {
	props := map[string]any{}
	for _, f := range fields {
		props[f] = map[string]any{"type": "object"}
	}
	return map[string]any{"type": "object", "properties": props}
}

// mergeOps combines GET/POST/PATCH/DELETE op maps into one path item.
func mergeOps(ops ...map[string]any) map[string]any {
	out := map[string]any{}
	for _, op := range ops {
		for k, v := range op {
			out[k] = v
		}
	}
	return out
}
