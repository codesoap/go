// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package json

// JSON value parser state machine.
// Just about at the limit of what is reasonable to write by hand.
// Some parts are a bit tedious, but overall it nicely factors out the
// otherwise common code from the multiple scanning functions
// in this package (Compact, Indent, checkValid, etc).
//
// This file starts with two simple examples using the scanner
// before diving into the scanner itself.

import (
	"strconv"
	"sync"
)

// Valid reports whether data is a valid JSON encoding.
func Valid(data []byte) bool {
	scan := newScanner()
	defer freeScanner(scan)
	return checkValid(data, scan) == nil
}

// checkValid verifies that data is valid JSON-encoded data.
// scan is passed in for use by checkValid to avoid an allocation.
func checkValid(data []byte, scan *scanner) error {
	scan.reset()
	for _, c := range data {
		scan.bytes++
		if scan.executeStep(c) == scanError {
			return scan.err
		}
	}
	if scan.eof() == scanError {
		return scan.err
	}
	return nil
}

// A SyntaxError is a description of a JSON syntax error.
type SyntaxError struct {
	msg    string // description of error
	Offset int64  // error occurred after reading Offset bytes
}

func (e *SyntaxError) Error() string { return e.msg }

// A scanner is a JSON scanning state machine.
// Callers call scan.reset and then pass bytes in one at a time
// by calling scan.step(&scan, c) for each byte.
// The return value, referred to as an opcode, tells the
// caller about significant parsing events like beginning
// and ending literals, objects, and arrays, so that the
// caller can follow along if it wishes.
// The return value scanEnd indicates that a single top-level
// JSON value has been completed, *before* the byte that
// just got passed in.  (The indication must be delayed in order
// to recognize the end of numbers: is 123 a whole value or
// the beginning of 12345e+6?).
type scanner struct {
	// Thes step is the action to be executed for the next transition.
	step int

	// Reached end of top-level value.
	endTop bool

	// Stack of what we're in the middle of - array values, object keys, object values.
	parseState []int

	// Error that happened, if any.
	err error

	// total bytes consumed, updated by decoder.Decode (and deliberately
	// not set to zero by scan.reset)
	bytes int64
}

var scannerPool = sync.Pool{
	New: func() interface{} {
		return &scanner{}
	},
}

func newScanner() *scanner {
	scan := scannerPool.Get().(*scanner)
	// scan.reset by design doesn't set bytes to zero
	scan.bytes = 0
	scan.reset()
	return scan
}

func freeScanner(scan *scanner) {
	// Avoid hanging on to too much memory in extreme cases.
	if len(scan.parseState) > 1024 {
		scan.parseState = nil
	}
	scannerPool.Put(scan)
}

// These values are stored in scanner.step.
const (
	stateBeginValueOrEmpty = iota
	stateBeginValue
	stateBeginStringOrEmpty
	stateBeginString
	stateEndValue
	stateEndTop
	stateInString
	stateInStringEsc
	stateInStringEscU
	stateInStringEscU1
	stateInStringEscU12
	stateInStringEscU123
	stateNeg
	state1
	state0
	stateDot
	stateDot0
	stateE
	stateESign
	stateE0
	stateT
	stateTr
	stateTru
	stateF
	stateFa
	stateFal
	stateFals
	stateN
	stateNu
	stateNul
	stateError
)

// These values are returned by the state transition functions
// assigned to scanner.state and the method scanner.eof.
// They give details about the current state of the scan that
// callers might be interested to know about.
// It is okay to ignore the return value of any particular
// call to scanner.state: if one call returns scanError,
// every subsequent call will return scanError too.
const (
	// Continue.
	scanContinue     = iota // uninteresting byte
	scanBeginLiteral        // end implied by next result != scanContinue
	scanBeginObject         // begin object
	scanObjectKey           // just finished object key (string)
	scanObjectValue         // just finished non-last object value
	scanEndObject           // end object (implies scanObjectValue if possible)
	scanBeginArray          // begin array
	scanArrayValue          // just finished array value
	scanEndArray            // end array (implies scanArrayValue if possible)
	scanSkipSpace           // space byte; can skip; known to be last "continue" result

	// Stop.
	scanEnd   // top-level value ended *before* this byte; known to be first "stop" result
	scanError // hit an error, scanner.err.
)

// These values are stored in the parseState stack.
// They give the current state of a composite value
// being scanned. If the parser is inside a nested value
// the parseState describes the nested state, outermost at entry 0.
const (
	parseObjectKey   = iota // parsing object key (before colon)
	parseObjectValue        // parsing object value (after colon)
	parseArrayValue         // parsing array value
)

// reset prepares the scanner for use.
// It must be called before calling s.step.
func (s *scanner) reset() {
	s.step = stateBeginValue
	s.parseState = s.parseState[0:0]
	s.err = nil
	s.endTop = false
}

// eof tells the scanner that the end of input has been reached.
// It returns a scan status just as s.step does.
func (s *scanner) eof() int {
	if s.err != nil {
		return scanError
	}
	if s.endTop {
		return scanEnd
	}
	s.executeStep(' ')
	if s.endTop {
		return scanEnd
	}
	if s.err == nil {
		s.err = &SyntaxError{"unexpected end of JSON input", s.bytes}
	}
	return scanError
}

// pushParseState pushes a new parse state p onto the parse stack.
func (s *scanner) pushParseState(p int) {
	s.parseState = append(s.parseState, p)
}

// popParseState pops a parse state (already obtained) off the stack
// and updates s.step accordingly.
func (s *scanner) popParseState() {
	n := len(s.parseState) - 1
	s.parseState = s.parseState[0:n]
	if n == 0 {
		s.step = stateEndTop
		s.endTop = true
	} else {
		s.step = stateEndValue
	}
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

func (s *scanner) executeStep(c byte) int {
	switch s.step {
	case stateBeginValueOrEmpty:
		// stateBeginValueOrEmpty is the state after reading `[`.
		if c <= ' ' && isSpace(c) {
			return scanSkipSpace
		}
		if c == ']' {
			s.step = stateEndValue
			return s.executeStep(c)
		}
		s.step = stateBeginValue
		return s.executeStep(c)
	case stateBeginValue:
		// stateBeginValue is the state at the beginning of the input.
		if c <= ' ' && isSpace(c) {
			return scanSkipSpace
		}
		switch c {
		case '{':
			s.step = stateBeginStringOrEmpty
			s.pushParseState(parseObjectKey)
			return scanBeginObject
		case '[':
			s.step = stateBeginValueOrEmpty
			s.pushParseState(parseArrayValue)
			return scanBeginArray
		case '"':
			s.step = stateInString
			return scanBeginLiteral
		case '-':
			s.step = stateNeg
			return scanBeginLiteral
		case '0': // beginning of 0.123
			s.step = state0
			return scanBeginLiteral
		case 't': // beginning of true
			s.step = stateT
			return scanBeginLiteral
		case 'f': // beginning of false
			s.step = stateF
			return scanBeginLiteral
		case 'n': // beginning of null
			s.step = stateN
			return scanBeginLiteral
		}
		if '1' <= c && c <= '9' { // beginning of 1234.5
			s.step = state1
			return scanBeginLiteral
		}
		return s.error(c, "looking for beginning of value")
	case stateBeginStringOrEmpty:
		// stateBeginStringOrEmpty is the state after reading `{`.
		if c <= ' ' && isSpace(c) {
			return scanSkipSpace
		}
		if c == '}' {
			n := len(s.parseState)
			s.parseState[n-1] = parseObjectValue
			s.step = stateEndValue
			return s.executeStep(c)
		}
		s.step = stateBeginString
		return s.executeStep(c)
	case stateBeginString:
		// stateBeginString is the state after reading `{"key": value,`.
		if c <= ' ' && isSpace(c) {
			return scanSkipSpace
		}
		if c == '"' {
			s.step = stateInString
			return scanBeginLiteral
		}
		return s.error(c, "looking for beginning of object key string")
	case stateEndValue:
		// stateEndValue is the state after completing a value,
		// such as after reading `{}` or `true` or `["x"`.
		n := len(s.parseState)
		if n == 0 {
			// Completed top-level before the current byte.
			s.step = stateEndTop
			s.endTop = true
			s.step = stateEndTop
			return s.executeStep(c)
		}
		if c <= ' ' && isSpace(c) {
			s.step = stateEndValue
			return scanSkipSpace
		}
		ps := s.parseState[n-1]
		switch ps {
		case parseObjectKey:
			if c == ':' {
				s.parseState[n-1] = parseObjectValue
				s.step = stateBeginValue
				return scanObjectKey
			}
			return s.error(c, "after object key")
		case parseObjectValue:
			if c == ',' {
				s.parseState[n-1] = parseObjectKey
				s.step = stateBeginString
				return scanObjectValue
			}
			if c == '}' {
				s.popParseState()
				return scanEndObject
			}
			return s.error(c, "after object key:value pair")
		case parseArrayValue:
			if c == ',' {
				s.step = stateBeginValue
				return scanArrayValue
			}
			if c == ']' {
				s.popParseState()
				return scanEndArray
			}
			return s.error(c, "after array element")
		}
		return s.error(c, "")
	case stateEndTop:
		// stateEndTop is the state after finishing the top-level value,
		// such as after reading `{}` or `[1,2,3]`.
		// Only space characters should be seen now.
		if !isSpace(c) {
			// Complain about non-space byte on next call.
			s.error(c, "after top-level value")
		}
		return scanEnd
	case stateInString:
		// stateInString is the state after reading `"`.
		if c == '"' {
			s.step = stateEndValue
			return scanContinue
		}
		if c == '\\' {
			s.step = stateInStringEsc
			return scanContinue
		}
		if c < 0x20 {
			return s.error(c, "in string literal")
		}
		return scanContinue
	case stateInStringEsc:
		// stateInStringEsc is the state after reading `"\` during a quoted string.
		switch c {
		case 'b', 'f', 'n', 'r', 't', '\\', '/', '"':
			s.step = stateInString
			return scanContinue
		case 'u':
			s.step = stateInStringEscU
			return scanContinue
		}
		return s.error(c, "in string escape code")
	case stateInStringEscU:
		// stateInStringEscU is the state after reading `"\u` during a quoted string.
		if '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' {
			s.step = stateInStringEscU1
			return scanContinue
		}
		// numbers
		return s.error(c, "in \\u hexadecimal character escape")
	case stateInStringEscU1:
		// stateInStringEscU1 is the state after reading `"\u1` during a quoted string.
		if '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' {
			s.step = stateInStringEscU12
			return scanContinue
		}
		// numbers
		return s.error(c, "in \\u hexadecimal character escape")
	case stateInStringEscU12:
		// stateInStringEscU12 is the state after reading `"\u12` during a quoted string.
		if '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' {
			s.step = stateInStringEscU123
			return scanContinue
		}
		// numbers
		return s.error(c, "in \\u hexadecimal character escape")
	case stateInStringEscU123:
		// stateInStringEscU123 is the state after reading `"\u123` during a quoted string.
		if '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' {
			s.step = stateInString
			return scanContinue
		}
		// numbers
		return s.error(c, "in \\u hexadecimal character escape")
	case stateNeg:
		// stateNeg is the state after reading `-` during a number.
		if c == '0' {
			s.step = state0
			return scanContinue
		}
		if '1' <= c && c <= '9' {
			s.step = state1
			return scanContinue
		}
		return s.error(c, "in numeric literal")
	case state1:
		// state1 is the state after reading a non-zero integer during a number,
		// such as after reading `1` or `100` but not `0`.
		if '0' <= c && c <= '9' {
			s.step = state1
			return scanContinue
		}
		s.step = state0
		return s.executeStep(c)
	case state0:
		// state0 is the state after reading `0` during a number.
		if c == '.' {
			s.step = stateDot
			return scanContinue
		}
		if c == 'e' || c == 'E' {
			s.step = stateE
			return scanContinue
		}
		s.step = stateEndValue
		return s.executeStep(c)
	case stateDot:
		// stateDot is the state after reading the integer and decimal point in a number,
		// such as after reading `1.`.
		if '0' <= c && c <= '9' {
			s.step = stateDot0
			return scanContinue
		}
		return s.error(c, "after decimal point in numeric literal")
	case stateDot0:
		// stateDot0 is the state after reading the integer, decimal point, and subsequent
		// digits of a number, such as after reading `3.14`.
		if '0' <= c && c <= '9' {
			return scanContinue
		}
		if c == 'e' || c == 'E' {
			s.step = stateE
			return scanContinue
		}
		s.step = stateEndValue
		return s.executeStep(c)
	case stateE:
		// stateE is the state after reading the mantissa and e in a number,
		// such as after reading `314e` or `0.314e`.
		if c == '+' || c == '-' {
			s.step = stateESign
			return scanContinue
		}
		s.step = stateESign
		return s.executeStep(c)
	case stateESign:
		// stateESign is the state after reading the mantissa, e, and sign in a number,
		// such as after reading `314e-` or `0.314e+`.
		if '0' <= c && c <= '9' {
			s.step = stateE0
			return scanContinue
		}
		return s.error(c, "in exponent of numeric literal")
	case stateE0:
		// stateE0 is the state after reading the mantissa, e, optional sign,
		// and at least one digit of the exponent in a number,
		// such as after reading `314e-2` or `0.314e+1` or `3.14e0`.
		if '0' <= c && c <= '9' {
			return scanContinue
		}
		s.step = stateEndValue
		return s.executeStep(c)
	case stateT:
		// stateT is the state after reading `t`.
		if c == 'r' {
			s.step = stateTr
			return scanContinue
		}
		return s.error(c, "in literal true (expecting 'r')")
	case stateTr:
		// stateTr is the state after reading `tr`.
		if c == 'u' {
			s.step = stateTru
			return scanContinue
		}
		return s.error(c, "in literal true (expecting 'u')")
	case stateTru:
		// stateTru is the state after reading `tru`.
		if c == 'e' {
			s.step = stateEndValue
			return scanContinue
		}
		return s.error(c, "in literal true (expecting 'e')")
	case stateF:
		// stateF is the state after reading `f`.
		if c == 'a' {
			s.step = stateFa
			return scanContinue
		}
		return s.error(c, "in literal false (expecting 'a')")
	case stateFa:
		// stateFa is the state after reading `fa`.
		if c == 'l' {
			s.step = stateFal
			return scanContinue
		}
		return s.error(c, "in literal false (expecting 'l')")
	case stateFal:
		// stateFal is the state after reading `fal`.
		if c == 's' {
			s.step = stateFals
			return scanContinue
		}
		return s.error(c, "in literal false (expecting 's')")
	case stateFals:
		// stateFals is the state after reading `fals`.
		if c == 'e' {
			s.step = stateEndValue
			return scanContinue
		}
		return s.error(c, "in literal false (expecting 'e')")
	case stateN:
		// stateN is the state after reading `n`.
		if c == 'u' {
			s.step = stateNu
			return scanContinue
		}
		return s.error(c, "in literal null (expecting 'u')")
	case stateNu:
		// stateNu is the state after reading `nu`.
		if c == 'l' {
			s.step = stateNul
			return scanContinue
		}
		return s.error(c, "in literal null (expecting 'l')")
	case stateNul:
		// stateNul is the state after reading `nul`.
		if c == 'l' {
			s.step = stateEndValue
			return scanContinue
		}
		return s.error(c, "in literal null (expecting 'l')")
	default:
		// s will be stateError here.
		// stateError is the state after reaching a syntax error,
		// such as after reading `[1}` or `5.1.2`.
		return scanError
	}
}

// error records an error and switches to the error state.
func (s *scanner) error(c byte, context string) int {
	s.step = stateError
	s.err = &SyntaxError{"invalid character " + quoteChar(c) + " " + context, s.bytes}
	return scanError
}

// quoteChar formats c as a quoted character literal
func quoteChar(c byte) string {
	// special cases - different from quoted strings
	if c == '\'' {
		return `'\''`
	}
	if c == '"' {
		return `'"'`
	}

	// use quoted string with different quotation marks
	s := strconv.Quote(string(c))
	return "'" + s[1:len(s)-1] + "'"
}
