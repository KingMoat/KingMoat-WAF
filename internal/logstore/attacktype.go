// Attack-type classification: maps a deny/challenge rule identifier to a
// human-readable attack category shown in the console and shipped with
// audit/access entries.
package logstore

import "strings"

// AttackTypeOf maps "<stage>/<rule>" (and raw Coraza rule ids) to a Chinese
// attack category. Unknown rules fall back to the stage name.
func attackTypeOf(rule string) string {
	r := strings.ToLower(rule)
	switch {
	case strings.HasPrefix(r, "semantic/sqli"):
		return "SQL注入"
	case strings.HasPrefix(r, "semantic/xss"):
		return "XSS跨站脚本"
	case strings.HasPrefix(r, "acl/"):
		return "IP封禁"
	case strings.HasPrefix(r, "auth/"):
		return "身份认证"
	case strings.HasPrefix(r, "ratelimit"):
		return "CC攻击"
	case strings.HasPrefix(r, "captcha/"):
		return "人机验证"
	case strings.HasPrefix(r, "bot"):
		return "BOT爬虫"
	case strings.HasPrefix(r, "geo/"):
		return "地域封禁"
	case strings.HasPrefix(r, "router/"):
		return "扫描探测"
	case strings.HasPrefix(r, "penalty/"):
		return "攻击惩罚"
	case strings.HasPrefix(r, "matcher/"):
		return "自定义规则"
	case strings.HasPrefix(r, "site/"):
		return "站点禁用"
	case strings.HasPrefix(r, "redirect/"):
		return "HTTPS跳转"
	case strings.HasPrefix(r, "proxy/"):
		return "协议防护"
	case strings.HasPrefix(r, "coraza/rule-") || isDigits(strings.TrimPrefix(r, "coraza/rule-")):
		return crsCategory(strings.TrimPrefix(r, "coraza/rule-"))
	case isDigits(r):
		return crsCategory(r)
	}
	return stageName(rule)
}

func stageName(rule string) string {
	if i := strings.Index(rule, "/"); i > 0 {
		return rule[:i]
	}
	if rule == "" {
		return "其他"
	}
	return rule
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// crsCategory buckets OWASP CRS rule ids (9xxNNN) into categories. Prefixes
// follow CRS 4.x: 920 protocol, 921 HTTP smuggling, 922/923 multipart/CR, 930
// LFI, 931 RFI, 932 RCE, 933 PHP, 934 NodeJS, 935 Java, 940 XEE, 941 XSS,
// 942 SQLi, 943 session fixation, 944 JS, 949/950 thresholds, 95x scanning.
func crsCategory(id string) string {
	if len(id) < 3 {
		return "其他"
	}
	switch id[:3] {
	case "930":
		return "本地文件包含"
	case "931":
		return "远程文件包含"
	case "932":
		return "命令注入"
	case "933":
		return "PHP注入"
	case "934":
		return "代码注入"
	case "935":
		return "Java注入"
	case "940":
		return "XEE攻击"
	case "941":
		return "XSS跨站脚本"
	case "942":
		return "SQL注入"
	case "943":
		return "会话固定"
	case "944":
		return "JS攻击"
	case "920":
		return "协议异常"
	case "921":
		return "HTTP走私"
	case "922", "923":
		return "多部分解析"
	case "955":
		return "扫描器"
	case "949", "980", "950", "951", "952", "953", "954", "959":
		return "综合评分"
	}
	return "其他"
}
