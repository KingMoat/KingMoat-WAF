package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// MCPHandler builds the streamable-HTTP MCP endpoint exposing the same
// hard-coded read-only tool table (sanitized outputs). Mount it behind the
// console auth middleware; the server instructions declare read-only.
func (s *Service) MCPHandler(version string) http.Handler {
	server := mcp.NewServer(&mcp.Implementation{Name: "kingmoat", Version: version}, nil)
	for _, t := range s.tools.Tools() {
		tool := t
		schema := json.RawMessage(tool.Parameters)
		server.AddTool(&mcp.Tool{
			Name:        tool.Name,
			Description: tool.Description + "（只读；输出已按企业脱敏策略处理，占位符不可在本端点复原）",
			InputSchema: schema,
		}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, _ := json.Marshal(req.Params.Arguments)
			out, err := s.tools.Execute(ctx, tool.Name, string(args))
			if err != nil {
				return &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(`{"error":%q}`, err.Error())}},
					IsError: true,
				}, nil
			}
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: out}},
			}, nil
		})
	}
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
}
