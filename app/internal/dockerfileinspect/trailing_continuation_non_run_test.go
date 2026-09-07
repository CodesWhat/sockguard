package dockerfileinspect

import "testing"

// TestContainsRunInstructionDanglingContinuationOfNonRunInstruction pins the
// post-loop tail check's final return (`instruction == "RUN" || instruction
// == "ONBUILD RUN"`) for the case where the leftover logical line is NOT a
// RUN instruction: a Dockerfile whose last physical line ends in an
// unresolved line-continuation (no following line to join with, and no
// trailing newline) still reaches that return with a non-empty, non-RUN
// logical line, and it must answer false. The existing "dangling
// continuation at eof" case in dockerfileinspect_test.go only exercises a RUN
// instruction there, which reads the same under both operands of the
// mutated `==`/`!=`; a non-RUN instruction is required to tell them apart.
func TestContainsRunInstructionDanglingContinuationOfNonRunInstruction(t *testing.T) {
	const in = "FROM alpine\nEXPOSE 80\\"
	if got := ContainsRunInstruction([]byte(in)); got {
		t.Fatalf("ContainsRunInstruction(%q) = true, want false (leftover logical line is EXPOSE, not RUN)", in)
	}
}
