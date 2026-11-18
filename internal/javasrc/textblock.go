// Package javasrc holds source-level rewrites shared by the Java readers.
//
// The three Java readers (audit inventory, restricted semantic model and the
// taint engine) each lex Java with text/scanner. None of them models the
// `"""` text-block delimiter, and each used to reject the whole file when one
// appeared, which silently removed every endpoint declared in that file. The
// rewrite below keeps the file analysable: block content is discarded (it is
// never code), the block becomes an empty string literal, and the newline
// count is preserved so token line numbers stay identical to the original.
package javasrc

import "bytes"

// TextBlockNote is appended to a reader's problem/boundary list when a file
// had at least one block neutralised. Readers must disclose it: the content
// was not analysed.
const TextBlockNote = "text_block_content_not_analyzed"

// Strip replaces every Java text block with an empty string literal that
// carries the same number of escaped newlines. It returns the rewritten source,
// the number of blocks neutralised, and false when a block is never closed
// (the caller must then reject the file as malformed).
func Strip(data []byte) ([]byte, int, bool) {
	var out bytes.Buffer
	out.Grow(len(data))
	blocks := 0
	for index := 0; index < len(data); {
		if index+2 < len(data) && data[index] == '"' && data[index+1] == '"' && data[index+2] == '"' {
			closing := bytes.Index(data[index+3:], []byte(`"""`))
			if closing < 0 {
				return nil, 0, false
			}
			content := data[index+3 : index+3+closing]
			// An empty literal plus the block's real newlines: the literal stays
			// on one line, and every following token keeps its original line
			// number because the newline count is unchanged.
			out.WriteString(`""`)
			for _, char := range content {
				if char == '\n' {
					out.WriteByte('\n')
				}
			}
			index += 3 + closing + 3
			blocks++
			continue
		}
		out.WriteByte(data[index])
		index++
	}
	return out.Bytes(), blocks, true
}
