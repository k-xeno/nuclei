package xss

import (
	"sort"
	"strings"

	"golang.org/x/net/html"
)

// DetectContextsRobust tokenizes the HTML response to find all places where our probe appears
// For each one, it figures out the context (like "inside a script tag" or "in an attribute")
func DetectContextsRobust(body string, smartCanary string) []ReflectionContext {
	contexts := []ReflectionContext{}

	// Extract base canary for position finding
	baseCanary := extractBaseCanary(smartCanary)

	// Find all canary positions using base canary
	// We use baseCanary (not smartCanary) because special chars might be partially encoded
	// Example: "xSs9K7j&lt;&gt;'" has encoded < and > but unencoded '
	// This is still exploitable via the quote, so we must detect it
	canaryPositions := findAllOccurrences(body, baseCanary)
	if len(canaryPositions) == 0 {
		return contexts
	}

	// Tokenize HTML and track state
	tokenizer := html.NewTokenizer(strings.NewReader(body))
	position := 0
	inScript := false
	inStyle := false
	inRCDATA := false // <textarea> and <title> need special handling
	var currentTag string
	inSVG := false
	inMathML := false
	scriptType := ""

	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			break
		}

		token := tokenizer.Token()
		tokenStart := position
		tokenRaw := tokenizer.Raw()
		position += len(tokenRaw)

		// Check if any canary is in this token
		for _, canaryPos := range canaryPositions {
			if canaryPos >= tokenStart && canaryPos < position {
				contextType := detectContextFromToken(token, tokenType, canaryPos-tokenStart, inScript, inStyle, inRCDATA, currentTag, inSVG, inMathML, scriptType, baseCanary)

				// Analyze which characters survived to detect active filters
				filterInfo := detectFilters(body, canaryPos, smartCanary)

				reflectionCtx := ReflectionContext{
					Type:         contextType,
					Location:     canaryPos,
					TagName:      currentTag,
					FilterBypass: filterInfo,
				}

				// Detect quote character for attribute contexts and refine context type
				if isAttributeContext(contextType) {
					quoteChar := detectQuoteChar(body, canaryPos)
					reflectionCtx.QuoteChar = quoteChar

					// Refine context type based on actual quote character
					if quoteChar == '\'' {
						reflectionCtx.Type = ContextHTMLAttrSingleQuoted
					} else if quoteChar == '"' {
						reflectionCtx.Type = ContextHTMLAttrDoubleQuoted
					} else {
						reflectionCtx.Type = ContextHTMLAttrUnquoted
					}
				}

				// Optimization: Only include exploitable contexts
				// Unquoted attributes are always considered exploitable (can inject handlers via space)
				if !reflectionCtx.FilterBypass.IsExploitable && reflectionCtx.Type != ContextHTMLAttrUnquoted {
					continue
				}
				contexts = append(contexts, reflectionCtx)
			}
		}

		// Update state machine
		if tokenType == html.StartTagToken || tokenType == html.SelfClosingTagToken {
			currentTag = token.Data

			// Track namespace changes (SVG/MathML)
			if token.Data == "svg" {
				inSVG = true
			} else if token.Data == "math" {
				inMathML = true
			}

			if token.Data == "script" {
				inScript = true
				// Check script type attribute
				scriptType = ""
				for _, attr := range token.Attr {
					if attr.Key == "type" {
						scriptType = strings.ToLower(attr.Val)
						break
					}
				}
			} else if token.Data == "style" {
				inStyle = true
			} else if token.Data == "textarea" || token.Data == "title" {
				inRCDATA = true
			}
		} else if tokenType == html.EndTagToken {
			if token.Data == "script" {
				inScript = false
				scriptType = ""
			} else if token.Data == "style" {
				inStyle = false
			} else if token.Data == "svg" {
				inSVG = false
			} else if token.Data == "math" {
				inMathML = false
			} else if token.Data == "textarea" || token.Data == "title" {
				inRCDATA = false
			}
		}
	}

	// Sort contexts by exploitability (easiest first)
	sort.Slice(contexts, func(i, j int) bool {
		return contexts[i].Type.ExploitabilityRank() < contexts[j].Type.ExploitabilityRank()
	})

	return contexts
}

// extractBaseCanary extracts the base canary without special characters
func extractBaseCanary(smartCanary string) string {
	// Smart canary format: "Nucl3iXXXXXX<>'\""
	// We need to extract "Nucl3iXXXXXX"
	// Find the position of the first special char
	for i, char := range smartCanary {
		if char == '<' || char == '>' || char == '\'' || char == '"' {
			return smartCanary[:i]
		}
	}
	return smartCanary
}

// findAllOccurrences finds all positions where the canary appears in the body
func findAllOccurrences(body, canary string) []int {
	var positions []int
	start := 0
	for {
		idx := strings.Index(body[start:], canary)
		if idx == -1 {
			break
		}
		actualIdx := start + idx
		positions = append(positions, actualIdx)
		start = actualIdx + 1 // Move past this occurrence
	}
	return positions
}

// detectContextFromToken determines the context type based on the HTML token
func detectContextFromToken(token html.Token, tokenType html.TokenType, offsetInToken int, inScript, inStyle, inRCDATA bool, currentTag string, inSVG, inMathML bool, scriptType string, baseCanary string) ContextType {
	switch tokenType {
	case html.TextToken:
		if inScript {
			// Check for JSON context within script tags
			if scriptType == "application/json" || scriptType == "text/json" {
				return ContextScriptJSON
			}
			return analyzeJSContext(string(token.Data), offsetInToken)
		}
		if inStyle {
			return ContextStyleProperty
		}
		if inRCDATA {
			return ContextRCDATA
		}
		return ContextHTMLText

	case html.StartTagToken, html.SelfClosingTagToken:
		// Check if canary is in an attribute value or name
		for _, attr := range token.Attr {
			if strings.Contains(attr.Val, baseCanary) {
				// The html.Tokenizer doesn't preserve quote information
				// We need to determine it from the attribute value context
				// Unquoted attributes have no spaces and end at whitespace or >
				// For now, we'll default to double-quoted and let detectQuoteChar refine it
				return ContextHTMLAttrDoubleQuoted
			}
			// Also check attribute name
			if strings.Contains(attr.Key, baseCanary) {
				return ContextHTMLAttrUnquoted
			}
		}
		return ContextHTMLText

	case html.CommentToken:
		return ContextHTMLComment

	default:
		return ContextUnknown
	}
}

// analyzeJSContext analyzes JavaScript context to determine if we're in a string or code
func analyzeJSContext(jsCode string, offset int) ContextType {
	// Look backward from offset to determine context
	if offset > len(jsCode) {
		offset = len(jsCode)
	}

	beforeCanary := jsCode[:offset]

	// Iterate through the code to track state
	var (
		inSingleQuote bool
		inDoubleQuote bool
		inBacktick    bool
		isEscaped     bool
	)

	for _, r := range beforeCanary {
		if isEscaped {
			isEscaped = false
			continue
		}

		if r == '\\' {
			isEscaped = true
			continue
		}

		// Toggle state based on quotes, but only if we're not inside another quote type
		switch r {
		case '\'':
			if !inDoubleQuote && !inBacktick {
				inSingleQuote = !inSingleQuote
			}
		case '"':
			if !inSingleQuote && !inBacktick {
				inDoubleQuote = !inDoubleQuote
			}
		case '`':
			if !inSingleQuote && !inDoubleQuote {
				inBacktick = !inBacktick
			}
		}
	}

	if inBacktick {
		return ContextScriptTemplateString
	}
	if inSingleQuote {
		return ContextScriptStringSingle
	}
	if inDoubleQuote {
		return ContextScriptStringDouble
	}

	return ContextScriptCode
}



// detectQuoteChar detects the quote character used in an attribute
// It properly handles nested quotes (polyglots) by finding the OPENING quote
func detectQuoteChar(body string, canaryPos int) rune {
	// Look backward to find the attribute start
	// Use 1000 chars to handle complex/long attributes
	searchStart := canaryPos - 1000
	if searchStart < 0 {
		searchStart = 0
	}
	snippet := body[searchStart:canaryPos]

	// Iterate to find the first quote that opens an attribute and doesn't close
	for i := 0; i < len(snippet); i++ {
		char := snippet[i]
		if char == '"' || char == '\'' {
			// Check if this quote is an attribute starter (preceded by =)
			isAttrStart := false
			// Scan backwards from quote ignoring space
			for j := i - 1; j >= 0; j-- {
				c := snippet[j]
				if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
					continue
				}
				if c == '=' {
					isAttrStart = true
				}
				break
			}

			if isAttrStart {
				// This is an attribute opening quote.
				// Check if it closes before the canary
				closingPos := strings.Index(snippet[i+1:], string(char))

				if closingPos == -1 {
					// No closing quote found -> Encloses canary -> Winner!
					return rune(char)
				}

				// It closes. Skip past it.
				i += closingPos + 1
			}
		}
	}

	return 0 // Unquoted
}

// detectFilters checks which special characters survived in the reflection
// This determines what filter bypasses are possible and overall exploitability
func detectFilters(body string, canaryPos int, smartCanary string) FilterBypassInfo {
	var (
		angleBracketsAllowed bool
		singleQuoteAllowed   bool
		doubleQuoteAllowed   bool
	)

	// Find the reflected region - limit search to avoid picking up HTML structure
	// Buffer accounts for HTML entity encoding (e.g., &lt; is 4 chars vs < is 1)
	maxEntityExpansion := 6 * 4 // 6 special chars * ~4 chars per entity
	searchEnd := canaryPos + len(smartCanary) + maxEntityExpansion
	if searchEnd > len(body) {
		searchEnd = len(body)
	}

	snippet := body[canaryPos:searchEnd]

	// Try to limit snippet to avoid HTML structure after the canary
	// Look for the end of the base canary content
	baseCanary := extractBaseCanary(smartCanary)
	idx := strings.Index(snippet, baseCanary)
	if idx != -1 {
		// Analyze text AFTER the base canary
		postCanary := snippet[idx+len(baseCanary):]

		// 1. Check Angle Brackets (< and >)
		// Find first occurrence of < or &lt;
		idxLit := strings.Index(postCanary, "<")
		idxEnc := strings.Index(postCanary, "&lt;")

		if idxLit != -1 && (idxEnc == -1 || idxLit < idxEnc) {
			// Literal < found first
			angleBracketsAllowed = true
		} else {
			// Encoded or missing
			angleBracketsAllowed = false
		}

		// 2. Check Single Quote (')
		idxLit = strings.Index(postCanary, "'")
		idxEnc = strings.Index(postCanary, "&#39;")
		if idxEnc == -1 {
			idxEnc = strings.Index(postCanary, "&apos;")
		}
		if idxEnc == -1 {
			idxEnc = strings.Index(postCanary, "&#x27;")
		}

		if idxLit != -1 && (idxEnc == -1 || idxLit < idxEnc) {
			singleQuoteAllowed = true
		} else {
			singleQuoteAllowed = false
		}

		// 3. Check Double Quote (")
		idxLit = strings.Index(postCanary, "\"")
		idxEnc = strings.Index(postCanary, "&quot;")
		if idxEnc == -1 {
			idxEnc = strings.Index(postCanary, "&#34;")
		}
		if idxEnc == -1 {
			idxEnc = strings.Index(postCanary, "&#x22;")
		}

		if idxLit != -1 && (idxEnc == -1 || idxLit < idxEnc) {
			doubleQuoteAllowed = true
		} else {
			doubleQuoteAllowed = false
		}
	} else {
		// Fallback if base canary not found (unlikely)
		// Use original logic but with strict checks (first occurrence wins)

		// 1. Check Angle Brackets (< and >)
		idxLit := strings.Index(snippet, "<")
		idxEnc := strings.Index(snippet, "&lt;")
		if idxLit != -1 && (idxEnc == -1 || idxLit < idxEnc) {
			angleBracketsAllowed = true
		} else {
			angleBracketsAllowed = false
		}

		// 2. Check Single Quote (')
		idxLit = strings.Index(snippet, "'")
		idxEnc = strings.Index(snippet, "&#39;")
		if idxEnc == -1 {
			idxEnc = strings.Index(snippet, "&apos;")
		}
		if idxEnc == -1 {
			idxEnc = strings.Index(snippet, "&#x27;")
		}
		if idxLit != -1 && (idxEnc == -1 || idxLit < idxEnc) {
			singleQuoteAllowed = true
		} else {
			singleQuoteAllowed = false
		}

		// 3. Check Double Quote (")
		idxLit = strings.Index(snippet, "\"")
		idxEnc = strings.Index(snippet, "&quot;")
		if idxEnc == -1 {
			idxEnc = strings.Index(snippet, "&#34;")
		}
		if idxEnc == -1 {
			idxEnc = strings.Index(snippet, "&#x22;")
		}
		if idxLit != -1 && (idxEnc == -1 || idxLit < idxEnc) {
			doubleQuoteAllowed = true
		} else {
			doubleQuoteAllowed = false
		}
	}

	// Determine blocked characters
	blockedChars := ""
	if !angleBracketsAllowed {
		blockedChars += "<>"
	}
	if !singleQuoteAllowed {
		blockedChars += "'"
	}
	if !doubleQuoteAllowed {
		blockedChars += "\""
	}

	// A context is exploitable if at least some XSS-critical chars are allowed
	// For HTML contexts, we need angle brackets
	// For attribute contexts, we need quotes
	// For script contexts, we need quotes and semicolons
	isExploitable := angleBracketsAllowed || singleQuoteAllowed || doubleQuoteAllowed

	return FilterBypassInfo{
		AngleBracketsAllowed: angleBracketsAllowed,
		SingleQuoteAllowed:   singleQuoteAllowed,
		DoubleQuoteAllowed:   doubleQuoteAllowed,
		IsExploitable:        isExploitable,
		BlockedChars:         blockedChars,
	}
}

// isAttributeContext checks if a context type is an attribute context
func isAttributeContext(ctx ContextType) bool {
	return ctx == ContextHTMLAttrDoubleQuoted ||
		ctx == ContextHTMLAttrSingleQuoted ||
		ctx == ContextHTMLAttrUnquoted
}
