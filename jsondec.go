// Package jsondec provides a reflection-at-registration JSON decoder optimized for
// repeated decoding into structs.
//
// Usage:
//
//	type User struct {
//	    ID   int    `json:"id,required"`
//	    Name string `json:"name"`
//	    Tags []int  `json:"tags"`
//	}
//
//	var DecodeUser = jsondec.RegisterDecoder[User]()
//
//	var u User
//	err := DecodeUser(rawJSON, &u)
//
// Reflection is used when RegisterDecoder is called. The returned decoder uses
// unsafe offsets and custom scanning on its normal primitive, struct, pointer,
// slice, and array paths. Runtime reflection is used only for cases that need
// dynamic Go type operations: arbitrary map assignment, custom unmarshaler
// interface calls, arbitrary pointer allocation for non-specialized dynamic types, arbitrary composite slice
// allocation, and fixed-array tail zeroing for element types without a fast
// specialized zero path.
//
// String scanning uses a two-stage design inspired by encoding/json/v2's
// jsonwire.ConsumeSimpleString: a tiny inlinable fast path with a 256-byte
// lookup table handles ordinary ASCII strings in one indexed load per byte,
// and the full scanner runs only when an escape, control byte, or high byte
// is encountered.
package jsondec

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"github.com/cespare/xxhash/v2"
)

// DecodeFunc decodes JSON bytes into dst.
type DecodeFunc[T any] func(raw []byte, dst *T) error

// DecoderOptions configures an opt-in decoder variant. The zero value preserves
// RegisterDecoder's compatibility and performance defaults: unknown struct
// fields are ignored, path strings are allocated only when errors are wrapped,
// and no structural size limits are enforced.
type DecoderOptions struct {
	// DisallowUnknownFields returns ErrUnknownField instead of skipping unknown
	// struct fields. The default is false.
	DisallowUnknownFields bool

	// MaxBytes rejects an input document, or an individual RawValue/RawObject/
	// RawArray/RawUnion value, whose raw JSON byte length exceeds this value.
	// A zero or negative value disables the check.
	MaxBytes int

	// MaxDepth rejects values nested deeper than this value when the scanner is
	// skipping or preserving opaque/raw JSON. A zero or negative value disables
	// the check.
	MaxDepth int

	// MaxObjectFields rejects skipped or raw JSON objects with more fields than
	// this value. A zero or negative value disables the check.
	MaxObjectFields int

	// MaxArrayLength rejects skipped or raw JSON arrays with more elements than
	// this value. A zero or negative value disables the check.
	MaxArrayLength int

	// ReuseInputBuffer makes decoded string and []byte values alias raw directly.
	// When a retained string contains escapes, the decoder may destructively
	// compact/unescape raw in place, so raw may no longer contain the original
	// JSON after Decode returns. The caller must keep raw alive and immutable
	// while decoded values are live. The default false copies raw once when the
	// target type can retain strings or []byte values.
	ReuseInputBuffer bool
}

// JSONKind is the top-level JSON token kind returned by Kind and RawUnion.
type JSONKind uint8

const (
	KindInvalid JSONKind = iota
	KindNull
	KindObject
	KindArray
	KindString
	KindNumber
	KindBool
)

// RawValue stores a validated JSON value without decoding it into Go maps,
// slices, or primitives. Bytes preserves the original raw JSON bytes for the
// value, including whitespace within the value. Present is set when the value
// was decoded as a struct field or root value.
type RawValue struct {
	Bytes   []byte
	Present bool
}

// RawObject stores a validated JSON object or null without decoding it. It is
// useful for schema-like extension payloads such as JSON Schema, metadata, and
// tool configuration objects.
type RawObject struct {
	Bytes   []byte
	Present bool
}

// RawArray stores a validated JSON array or null without decoding it.
type RawArray struct {
	Bytes   []byte
	Present bool
}

// Present records whether a JSON field was present and whether it was explicit
// JSON null. Non-null values are validated and skipped without being stored.
type Present struct {
	Present bool
	Null    bool
}

// Forbidden marks a known JSON field as explicitly forbidden. If the field is
// present, decoding stops with ErrForbiddenField.
type Forbidden struct{}

// Optional records whether a JSON field was present. If present, Value is
// decoded using the normal rules for T; explicit null is accepted only when T's
// own decoder accepts null.
type Optional[T any] struct {
	Present bool
	Value   T
}

// Nullable records explicit JSON null separately from a non-null decoded Value.
// It does not by itself distinguish omitted fields; use OptionalNullable for
// omitted-vs-null-vs-value compatibility fields.
type Nullable[T any] struct {
	Null  bool
	Value T
}

// OptionalNullable records omitted, explicit null, and non-null decoded value.
type OptionalNullable[T any] struct {
	Present bool
	Null    bool
	Value   T
}

// RawUnion stores any validated JSON value plus its top-level kind. It is a
// low-level building block for API-layer union fields that need procedural
// semantic handling after parse.
type RawUnion struct {
	Kind  JSONKind
	Bytes []byte
}

// StringOrSlice decodes either a JSON string or an array of T.
type StringOrSlice[T any] struct {
	IsString bool
	String   string
	Slice    []T
}

// StringOrObject decodes either a JSON string or an object T.
type StringOrObject[T any] struct {
	IsString bool
	String   string
	Object   T
}

// RegisterDecoder reflects over T once and returns a reusable, concurrent-safe decoder.
// T may be a struct or a pointer to a supported value type. The common decode
// paths avoid reflection; see the package comment for the remaining fallback cases.
func RegisterDecoder[T any]() DecodeFunc[T] {
	return RegisterDecoderOptions[T](DecoderOptions{})
}

// RegisterDecoderOptions is RegisterDecoder with opt-in decoding behavior such
// as strict unknown-field rejection and structural limits. Strictness is an
// option rather than a separate registration function so callers have a single
// registration surface.
func RegisterDecoderOptions[T any](opts DecoderOptions) DecodeFunc[T] {
	compileMu.Lock()
	ti, err := compileRootType(typeOf[T]())
	compileMu.Unlock()
	if err != nil {
		panic(err)
	}
	return func(raw []byte, dst *T) error {
		if dst == nil {
			return Error{Code: ErrNilDestination, Offset: 0}
		}
		if err := checkMaxBytes(opts, len(raw), 0); err != nil {
			return err
		}
		buf, mutable := decodeBuffer(raw, ti, opts)
		p := parser{buf: buf, n: len(buf), mutable: mutable, opts: opts}
		if err := p.decodeInto(ti, unsafe.Pointer(dst)); err != nil {
			return err
		}
		p.skipWS()
		if p.i != p.n {
			return Error{Code: ErrTrailingData, Offset: p.i}
		}
		return nil
	}
}

func typeOf[T any]() reflect.Type {
	return reflect.TypeOf((*T)(nil)).Elem()
}

func decodeBuffer(raw []byte, ti *typeInfo, opts DecoderOptions) ([]byte, bool) {
	if ti == nil || !ti.retainsBufferRefs {
		return raw, false
	}
	if opts.ReuseInputBuffer {
		return raw, true
	}
	buf := append([]byte(nil), raw...)
	return buf, true
}

// Kind returns the top-level JSON kind after leading whitespace. It does not
// fully validate the value; use Valid to check complete JSON validity.
func Kind(raw []byte) JSONKind {
	p := parser{buf: raw, n: len(raw)}
	return p.peekKind()
}

// IsNull reports whether raw's top-level token is JSON null.
func IsNull(raw []byte) bool { return Kind(raw) == KindNull }

// IsObject reports whether raw's top-level token is a JSON object.
func IsObject(raw []byte) bool { return Kind(raw) == KindObject }

// IsArray reports whether raw's top-level token is a JSON array.
func IsArray(raw []byte) bool { return Kind(raw) == KindArray }

// Valid reports whether raw is exactly one valid JSON value with only trailing
// whitespace after it.
func Valid(raw []byte) bool {
	p := parser{buf: raw, n: len(raw)}
	if err := p.skipValue(); err != nil {
		return false
	}
	p.skipWS()
	return p.i == p.n
}

// DecodeString decodes raw as a JSON string and rejects trailing non-whitespace.
func DecodeString(raw []byte) (string, error) {
	buf := append([]byte(nil), raw...)
	p := parser{buf: buf, n: len(buf), mutable: true}
	p.skipWS()
	b, err := p.parseStringFully()
	if err != nil {
		return "", err
	}
	p.skipWS()
	if p.i != p.n {
		return "", Error{Code: ErrTrailingData, Offset: p.i}
	}
	return unsafeBytesToString(b), nil
}

// DecodeStringSlice decodes raw as []string using jsondec's scanner.
func DecodeStringSlice(raw []byte) ([]string, error) {
	var out []string
	if err := DecodeInto(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// DecodeInto decodes raw into dst using jsondec's registered type compiler. It is
// intended for custom union decoders that need access to jsondec mechanics without
// falling back to encoding/json.
func DecodeInto[T any](raw []byte, dst *T) error {
	return DecodeIntoOptions(raw, dst, DecoderOptions{})
}

// DecodeIntoOptions is DecodeInto with opt-in decoder options.
func DecodeIntoOptions[T any](raw []byte, dst *T, opts DecoderOptions) error {
	if dst == nil {
		return Error{Code: ErrNilDestination, Offset: 0}
	}
	if err := checkMaxBytes(opts, len(raw), 0); err != nil {
		return err
	}
	ti, err := cachedTypeInfo(typeOf[T]())
	if err != nil {
		return err
	}
	buf, mutable := decodeBuffer(raw, ti, opts)
	p := parser{buf: buf, n: len(buf), mutable: mutable, opts: opts}
	if err := p.decodeInto(ti, unsafe.Pointer(dst)); err != nil {
		return err
	}
	p.skipWS()
	if p.i != p.n {
		return Error{Code: ErrTrailingData, Offset: p.i}
	}
	return nil
}

// DecodeObject decodes raw as an object or null into dst. The destination type
// controls whether null is accepted.
func DecodeObject[T any](raw []byte, dst *T) error {
	k := Kind(raw)
	if k != KindObject && k != KindNull {
		return Error{Code: ErrExpectedObject, Offset: firstNonSpace(raw)}
	}
	return DecodeInto(raw, dst)
}

// DecodeArray decodes raw as an array or null into dst. The destination type
// controls whether null is accepted.
func DecodeArray[T any](raw []byte, dst *[]T) error {
	k := Kind(raw)
	if k != KindArray && k != KindNull {
		return Error{Code: ErrExpectedArray, Offset: firstNonSpace(raw)}
	}
	return DecodeInto(raw, dst)
}

// DecodeStringEnum decodes raw as a string and validates it against allowed.
func DecodeStringEnum(raw []byte, allowed ...string) (string, error) {
	v, err := DecodeString(raw)
	if err != nil {
		return "", err
	}
	for _, a := range allowed {
		if v == a {
			return v, nil
		}
	}
	return "", Error{Code: ErrInvalidLiteral, Offset: firstNonSpace(raw)}
}

func cachedTypeInfo(t reflect.Type) (*typeInfo, error) {
	if v, ok := typeInfoCache.Load(t); ok {
		return v.(*typeInfo), nil
	}
	compileMu.Lock()
	defer compileMu.Unlock()
	if v, ok := typeInfoCache.Load(t); ok {
		return v.(*typeInfo), nil
	}
	ti, err := compileTypeInfo(t)
	if err != nil {
		return nil, CompileError{Type: t, Err: err}
	}
	ensureDecoder(ti)
	typeInfoCache.Store(t, ti)
	return ti, nil
}

func firstNonSpace(raw []byte) int {
	for i, c := range raw {
		switch c {
		case ' ', '\n', '\r', '\t':
			continue
		default:
			return i
		}
	}
	return len(raw)
}

// ErrorCode is a compact parse or registration-independent error code.
type ErrorCode uint8

const (
	ErrUnexpectedEOF ErrorCode = iota + 1
	ErrExpectedObject
	ErrExpectedArray
	ErrExpectedString
	ErrExpectedColon
	ErrExpectedCommaOrEnd
	ErrInvalidString
	ErrInvalidEscape
	ErrInvalidUnicodeEscape
	ErrInvalidNumber
	ErrNumberOverflow
	ErrInvalidLiteral
	ErrInvalidNull
	ErrRequiredFieldMissing
	ErrArrayTooLong
	ErrTrailingData
	ErrNilDestination
	ErrUnsupportedType
	ErrUnknownField
	ErrValueTooLarge
	ErrMaxDepth
	ErrObjectTooLarge
	ErrExpectedStringOrArray
	ErrExpectedStringOrObject
	ErrForbiddenField
)

// Error is the compact error returned by decoders. It formats text only when
// Error is called.
type Error struct {
	Code   ErrorCode
	Offset int
	Field  []byte
	Path   string
}

func (e Error) Error() string {
	msg := errorMessage(e.Code)
	if e.Path != "" {
		return fmt.Sprintf("jsondec: %s at byte %d at path %s", msg, e.Offset, e.Path)
	}
	if len(e.Field) > 0 {
		return fmt.Sprintf("jsondec: %s at byte %d near field %q", msg, e.Offset, e.Field)
	}
	return fmt.Sprintf("jsondec: %s at byte %d", msg, e.Offset)
}

func errorMessage(c ErrorCode) string {
	switch c {
	case ErrUnexpectedEOF:
		return "unexpected end of input"
	case ErrExpectedObject:
		return "expected object"
	case ErrExpectedArray:
		return "expected array"
	case ErrExpectedString:
		return "expected string"
	case ErrExpectedColon:
		return "expected colon"
	case ErrExpectedCommaOrEnd:
		return "expected comma or end"
	case ErrInvalidString:
		return "invalid string"
	case ErrInvalidEscape:
		return "invalid escape"
	case ErrInvalidUnicodeEscape:
		return "invalid unicode escape"
	case ErrInvalidNumber:
		return "invalid number"
	case ErrNumberOverflow:
		return "number overflow"
	case ErrInvalidLiteral:
		return "invalid literal"
	case ErrInvalidNull:
		return "invalid null"
	case ErrRequiredFieldMissing:
		return "required field missing"
	case ErrArrayTooLong:
		return "array too long"
	case ErrTrailingData:
		return "trailing data"
	case ErrNilDestination:
		return "nil destination"
	case ErrUnsupportedType:
		return "unsupported type"
	case ErrUnknownField:
		return "unknown field"
	case ErrValueTooLarge:
		return "value too large"
	case ErrMaxDepth:
		return "maximum depth exceeded"
	case ErrObjectTooLarge:
		return "object has too many fields"
	case ErrExpectedStringOrArray:
		return "expected string or array"
	case ErrExpectedStringOrObject:
		return "expected string or object"
	case ErrForbiddenField:
		return "forbidden field"
	default:
		return "unknown error"
	}
}

// CompileError is returned via panic from RegisterDecoder when T cannot be compiled.
type CompileError struct {
	Type  reflect.Type
	Field string
	Err   error
}

func (e CompileError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("jsondec: cannot compile %s.%s: %v", e.Type, e.Field, e.Err)
	}
	return fmt.Sprintf("jsondec: cannot compile %s: %v", e.Type, e.Err)
}

var (
	errUnsupported = errors.New("unsupported type")
)

type kind uint8

const (
	kindInvalid kind = iota
	kindBool
	kindInt
	kindInt8
	kindInt16
	kindInt32
	kindInt64
	kindUint
	kindUint8
	kindUint16
	kindUint32
	kindUint64
	kindFloat32
	kindFloat64
	kindString
	kindBytes
	kindStruct
	kindPtr
	kindSlice
	kindArray
	kindMap
	kindAny
	kindTime
	kindJSONNumber
	kindRawValue
	kindRawObject
	kindRawArray
	kindOptional
	kindNullable
	kindOptionalNullable
	kindRawUnion
	kindPresent
	kindForbidden
	kindStringOrSlice
	kindStringOrObject
	kindJSONUnmarshaler
	kindTextUnmarshaler
)

type decoderFunc func(*parser, unsafe.Pointer) error

type typeInfo struct {
	kind              kind
	typ               reflect.Type
	decode            decoderFunc
	retainsBufferRefs bool
	elem              *typeInfo
	alt               *typeInfo
	alloc             func() unsafe.Pointer // precompiled nil-pointer allocator for kindPtr
	zero              func(unsafe.Pointer)
	schema            *schema
	len               int // fixed array length

	presentOffset  uintptr
	nullOffset     uintptr
	valueOffset    uintptr
	bytesOffset    uintptr
	kindOffset     uintptr
	isStringOffset uintptr
	stringOffset   uintptr
	sliceOffset    uintptr
	objectOffset   uintptr
}

type fieldMeta struct {
	name       []byte
	hash       uint64
	offset     uintptr
	info       *typeInfo
	decode     decoderFunc
	required   bool
	requiredIx uint8
}

type hashEntry struct {
	hash  uint64
	index int
	used  bool
}

type smallLookupEntry struct {
	sig     uint32
	indices []int
}

type schema struct {
	typ          reflect.Type
	fields       []fieldMeta
	table        []hashEntry
	smallLookup  []smallLookupEntry
	requiredMask uint64
	resetFields  []int
}

var (
	compileMu     sync.Mutex
	structCache   = map[reflect.Type]*schema{}
	typeInfoCache sync.Map

	timeType       = reflect.TypeOf(time.Time{})
	jsonNumberType = reflect.TypeOf(json.Number(""))
	rawValueType   = reflect.TypeOf(RawValue{})
	rawObjectType  = reflect.TypeOf(RawObject{})
	rawArrayType   = reflect.TypeOf(RawArray{})
	rawUnionType   = reflect.TypeOf(RawUnion{})
	presentType    = reflect.TypeOf(Present{})
	forbiddenType  = reflect.TypeOf(Forbidden{})
	jsondecPkgPath   = rawValueType.PkgPath()

	jsonUnmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	textUnmarshalerType = reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()

	mapStringStringType  = reflect.TypeOf(map[string]string(nil))
	mapStringIntType     = reflect.TypeOf(map[string]int(nil))
	mapStringInt64Type   = reflect.TypeOf(map[string]int64(nil))
	mapStringUint64Type  = reflect.TypeOf(map[string]uint64(nil))
	mapStringFloat64Type = reflect.TypeOf(map[string]float64(nil))
	mapStringBoolType    = reflect.TypeOf(map[string]bool(nil))
)

func compileRootType(t reflect.Type) (*typeInfo, error) {
	ti, err := compileTypeInfo(t)
	if err != nil {
		return nil, CompileError{Type: t, Err: err}
	}
	if ti.kind != kindStruct && ti.kind != kindPtr {
		return nil, CompileError{Type: t, Err: errUnsupported}
	}
	ensureDecoder(ti)
	return ti, nil
}

func compileType(t reflect.Type) (*schema, error) {
	if t.Kind() != reflect.Struct {
		return nil, CompileError{Type: t, Err: errUnsupported}
	}
	if s := structCache[t]; s != nil {
		return s, nil
	}
	s := &schema{typ: t}
	structCache[t] = s // allow recursive structs through pointers
	ok := false
	defer func() {
		if !ok {
			delete(structCache, t)
		}
	}()

	requiredCount := 0
	seenNames := map[string]struct{}{}
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		if sf.PkgPath != "" { // unexported
			continue
		}
		name, required, skip := parseJSONTag(sf)
		if skip {
			continue
		}
		if _, exists := seenNames[name]; exists {
			return nil, CompileError{Type: t, Field: sf.Name, Err: fmt.Errorf("duplicate json field name %q", name)}
		}
		seenNames[name] = struct{}{}
		ti, err := compileTypeInfo(sf.Type)
		if err != nil {
			return nil, CompileError{Type: t, Field: sf.Name, Err: err}
		}
		if required && requiredCount >= 64 {
			return nil, CompileError{Type: t, Field: sf.Name, Err: errors.New("only 64 required fields are supported")}
		}
		fm := fieldMeta{
			name:     []byte(name),
			hash:     xxhash.Sum64([]byte(name)),
			offset:   sf.Offset,
			info:     ti,
			required: required,
		}
		if required {
			fm.requiredIx = uint8(requiredCount)
			s.requiredMask |= uint64(1) << fm.requiredIx
			requiredCount++
		}
		s.fields = append(s.fields, fm)
		if needsReset(ti.kind) {
			s.resetFields = append(s.resetFields, len(s.fields)-1)
		}
	}
	s.buildTable()
	ok = true
	return s, nil
}

func compileTypeInfo(t reflect.Type) (*typeInfo, error) {
	if t == timeType {
		return &typeInfo{kind: kindTime, typ: t}, nil
	}
	if t == jsonNumberType {
		return &typeInfo{kind: kindJSONNumber, typ: t}, nil
	}
	if ti, ok, err := compileSpecialjsondecType(t); ok || err != nil {
		return ti, err
	}
	if t.Kind() != reflect.Interface && t.Kind() != reflect.Pointer && (t.Implements(jsonUnmarshalerType) || reflect.PointerTo(t).Implements(jsonUnmarshalerType)) {
		return &typeInfo{kind: kindJSONUnmarshaler, typ: t}, nil
	}
	if t.Kind() != reflect.Interface && t.Kind() != reflect.Pointer && (t.Implements(textUnmarshalerType) || reflect.PointerTo(t).Implements(textUnmarshalerType)) {
		return &typeInfo{kind: kindTextUnmarshaler, typ: t}, nil
	}

	switch t.Kind() {
	case reflect.Bool:
		return &typeInfo{kind: kindBool, typ: t}, nil
	case reflect.Int:
		return &typeInfo{kind: kindInt, typ: t}, nil
	case reflect.Int8:
		return &typeInfo{kind: kindInt8, typ: t}, nil
	case reflect.Int16:
		return &typeInfo{kind: kindInt16, typ: t}, nil
	case reflect.Int32:
		return &typeInfo{kind: kindInt32, typ: t}, nil
	case reflect.Int64:
		return &typeInfo{kind: kindInt64, typ: t}, nil
	case reflect.Uint:
		return &typeInfo{kind: kindUint, typ: t}, nil
	case reflect.Uint8:
		return &typeInfo{kind: kindUint8, typ: t}, nil
	case reflect.Uint16:
		return &typeInfo{kind: kindUint16, typ: t}, nil
	case reflect.Uint32:
		return &typeInfo{kind: kindUint32, typ: t}, nil
	case reflect.Uint64, reflect.Uintptr:
		return &typeInfo{kind: kindUint64, typ: t}, nil
	case reflect.Float32:
		return &typeInfo{kind: kindFloat32, typ: t}, nil
	case reflect.Float64:
		return &typeInfo{kind: kindFloat64, typ: t}, nil
	case reflect.String:
		return &typeInfo{kind: kindString, typ: t}, nil
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return &typeInfo{kind: kindBytes, typ: t}, nil
		}
		elem, err := compileTypeInfo(t.Elem())
		if err != nil {
			return nil, err
		}
		return &typeInfo{kind: kindSlice, typ: t, elem: elem}, nil
	case reflect.Array:
		elem, err := compileTypeInfo(t.Elem())
		if err != nil {
			return nil, err
		}
		return &typeInfo{kind: kindArray, typ: t, elem: elem, len: t.Len()}, nil
	case reflect.Struct:
		sc, err := compileType(t)
		if err != nil {
			return nil, err
		}
		return &typeInfo{kind: kindStruct, typ: t, schema: sc}, nil
	case reflect.Pointer:
		elem, err := compileTypeInfo(t.Elem())
		if err != nil {
			return nil, err
		}
		return &typeInfo{kind: kindPtr, typ: t, elem: elem, alloc: makePointerAllocator(t.Elem(), elem)}, nil
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			return nil, errors.New("only maps with string keys are supported")
		}
		elem, err := compileTypeInfo(t.Elem())
		if err != nil {
			return nil, err
		}
		return &typeInfo{kind: kindMap, typ: t, elem: elem}, nil
	case reflect.Interface:
		if t.NumMethod() == 0 {
			return &typeInfo{kind: kindAny, typ: t}, nil
		}
		return nil, errors.New("only empty interfaces are supported unless they implement json.Unmarshaler")
	default:
		return nil, errUnsupported
	}
}

func compileSpecialjsondecType(t reflect.Type) (*typeInfo, bool, error) {
	if t == rawValueType {
		return compileRawType(t, kindRawValue), true, nil
	}
	if t == rawObjectType {
		return compileRawType(t, kindRawObject), true, nil
	}
	if t == rawArrayType {
		return compileRawType(t, kindRawArray), true, nil
	}
	if t == rawUnionType {
		bytesField, _ := t.FieldByName("Bytes")
		kindField, _ := t.FieldByName("Kind")
		return &typeInfo{
			kind:        kindRawUnion,
			typ:         t,
			bytesOffset: bytesField.Offset,
			kindOffset:  kindField.Offset,
			zero:        makeZeroer(t),
		}, true, nil
	}
	if t == presentType {
		presentField, _ := t.FieldByName("Present")
		nullField, _ := t.FieldByName("Null")
		return &typeInfo{
			kind:          kindPresent,
			typ:           t,
			presentOffset: presentField.Offset,
			nullOffset:    nullField.Offset,
			zero:          makeZeroer(t),
		}, true, nil
	}
	if t == forbiddenType {
		return &typeInfo{kind: kindForbidden, typ: t}, true, nil
	}
	if isjsondecGeneric(t, "Optional") {
		valueField, ok := t.FieldByName("Value")
		if !ok {
			return nil, true, errors.New("jsondec.Optional must have a Value field")
		}
		presentField, ok := t.FieldByName("Present")
		if !ok {
			return nil, true, errors.New("jsondec.Optional must have a Present field")
		}
		elem, err := compileTypeInfo(valueField.Type)
		if err != nil {
			return nil, true, err
		}
		return &typeInfo{
			kind:          kindOptional,
			typ:           t,
			elem:          elem,
			zero:          makeZeroer(t),
			presentOffset: presentField.Offset,
			valueOffset:   valueField.Offset,
		}, true, nil
	}
	if isjsondecGeneric(t, "Nullable") {
		valueField, ok := t.FieldByName("Value")
		if !ok {
			return nil, true, errors.New("jsondec.Nullable must have a Value field")
		}
		nullField, ok := t.FieldByName("Null")
		if !ok {
			return nil, true, errors.New("jsondec.Nullable must have a Null field")
		}
		elem, err := compileTypeInfo(valueField.Type)
		if err != nil {
			return nil, true, err
		}
		return &typeInfo{
			kind:        kindNullable,
			typ:         t,
			elem:        elem,
			zero:        makeZeroer(t),
			nullOffset:  nullField.Offset,
			valueOffset: valueField.Offset,
		}, true, nil
	}
	if isjsondecGeneric(t, "OptionalNullable") {
		valueField, ok := t.FieldByName("Value")
		if !ok {
			return nil, true, errors.New("jsondec.OptionalNullable must have a Value field")
		}
		presentField, ok := t.FieldByName("Present")
		if !ok {
			return nil, true, errors.New("jsondec.OptionalNullable must have a Present field")
		}
		nullField, ok := t.FieldByName("Null")
		if !ok {
			return nil, true, errors.New("jsondec.OptionalNullable must have a Null field")
		}
		elem, err := compileTypeInfo(valueField.Type)
		if err != nil {
			return nil, true, err
		}
		return &typeInfo{
			kind:          kindOptionalNullable,
			typ:           t,
			elem:          elem,
			zero:          makeZeroer(t),
			presentOffset: presentField.Offset,
			nullOffset:    nullField.Offset,
			valueOffset:   valueField.Offset,
		}, true, nil
	}
	if isjsondecGeneric(t, "StringOrSlice") {
		isStringField, ok := t.FieldByName("IsString")
		if !ok {
			return nil, true, errors.New("jsondec.StringOrSlice must have an IsString field")
		}
		stringField, ok := t.FieldByName("String")
		if !ok {
			return nil, true, errors.New("jsondec.StringOrSlice must have a String field")
		}
		sliceField, ok := t.FieldByName("Slice")
		if !ok {
			return nil, true, errors.New("jsondec.StringOrSlice must have a Slice field")
		}
		sliceInfo, err := compileTypeInfo(sliceField.Type)
		if err != nil {
			return nil, true, err
		}
		return &typeInfo{
			kind:           kindStringOrSlice,
			typ:            t,
			alt:            sliceInfo,
			zero:           makeZeroer(t),
			isStringOffset: isStringField.Offset,
			stringOffset:   stringField.Offset,
			sliceOffset:    sliceField.Offset,
		}, true, nil
	}
	if isjsondecGeneric(t, "StringOrObject") {
		isStringField, ok := t.FieldByName("IsString")
		if !ok {
			return nil, true, errors.New("jsondec.StringOrObject must have an IsString field")
		}
		stringField, ok := t.FieldByName("String")
		if !ok {
			return nil, true, errors.New("jsondec.StringOrObject must have a String field")
		}
		objectField, ok := t.FieldByName("Object")
		if !ok {
			return nil, true, errors.New("jsondec.StringOrObject must have an Object field")
		}
		objectInfo, err := compileTypeInfo(objectField.Type)
		if err != nil {
			return nil, true, err
		}
		return &typeInfo{
			kind:           kindStringOrObject,
			typ:            t,
			alt:            objectInfo,
			zero:           makeZeroer(t),
			isStringOffset: isStringField.Offset,
			stringOffset:   stringField.Offset,
			objectOffset:   objectField.Offset,
		}, true, nil
	}
	return nil, false, nil
}

func compileRawType(t reflect.Type, k kind) *typeInfo {
	bytesField, _ := t.FieldByName("Bytes")
	presentField, _ := t.FieldByName("Present")
	return &typeInfo{
		kind:          k,
		typ:           t,
		bytesOffset:   bytesField.Offset,
		presentOffset: presentField.Offset,
		zero:          makeZeroer(t),
	}
}

func isjsondecGeneric(t reflect.Type, name string) bool {
	return t.Kind() == reflect.Struct && t.PkgPath() == jsondecPkgPath && strings.HasPrefix(t.Name(), name+"[")
}

func makeZeroer(t reflect.Type) func(unsafe.Pointer) {
	return func(ptr unsafe.Pointer) {
		reflect.NewAt(t, ptr).Elem().SetZero()
	}
}

func needsReset(k kind) bool {
	switch k {
	case kindRawValue, kindRawObject, kindRawArray,
		kindOptional, kindNullable, kindOptionalNullable,
		kindRawUnion, kindPresent, kindStringOrSlice, kindStringOrObject:
		return true
	default:
		return false
	}
}

func makePointerAllocator(t reflect.Type, elem *typeInfo) func() unsafe.Pointer {
	// For primitive and common built-in layouts, use typed new(T) closures compiled
	// once at registration time. This keeps nil-pointer allocation out of the
	// reflection path without adding a kind switch to decodePtr.
	switch elem.kind {
	case kindBool:
		return func() unsafe.Pointer { v := new(bool); return unsafe.Pointer(v) }
	case kindInt:
		return func() unsafe.Pointer { v := new(int); return unsafe.Pointer(v) }
	case kindInt8:
		return func() unsafe.Pointer { v := new(int8); return unsafe.Pointer(v) }
	case kindInt16:
		return func() unsafe.Pointer { v := new(int16); return unsafe.Pointer(v) }
	case kindInt32:
		return func() unsafe.Pointer { v := new(int32); return unsafe.Pointer(v) }
	case kindInt64:
		return func() unsafe.Pointer { v := new(int64); return unsafe.Pointer(v) }
	case kindUint:
		return func() unsafe.Pointer { v := new(uint); return unsafe.Pointer(v) }
	case kindUint8:
		return func() unsafe.Pointer { v := new(uint8); return unsafe.Pointer(v) }
	case kindUint16:
		return func() unsafe.Pointer { v := new(uint16); return unsafe.Pointer(v) }
	case kindUint32:
		return func() unsafe.Pointer { v := new(uint32); return unsafe.Pointer(v) }
	case kindUint64:
		return func() unsafe.Pointer { v := new(uint64); return unsafe.Pointer(v) }
	case kindFloat32:
		return func() unsafe.Pointer { v := new(float32); return unsafe.Pointer(v) }
	case kindFloat64:
		return func() unsafe.Pointer { v := new(float64); return unsafe.Pointer(v) }
	case kindString:
		return func() unsafe.Pointer { v := new(string); return unsafe.Pointer(v) }
	case kindBytes:
		return func() unsafe.Pointer { v := new([]byte); return unsafe.Pointer(v) }
	case kindTime:
		return func() unsafe.Pointer { v := new(time.Time); return unsafe.Pointer(v) }
	case kindJSONNumber:
		return func() unsafe.Pointer { v := new(json.Number); return unsafe.Pointer(v) }
	}

	// Go's allocator needs the runtime type metadata for arbitrary pointer-bearing
	// structs, arrays, slices, maps, and custom unmarshaler values. Without code
	// generation there is no safe way to allocate those dynamic types with new(T),
	// so keep reflection as the fallback for exactly those cases.
	return func() unsafe.Pointer {
		return reflect.New(t).UnsafePointer()
	}
}

func parseJSONTag(sf reflect.StructField) (name string, required bool, skip bool) {
	tag := sf.Tag.Get("json")
	if tag == "-" {
		return "", false, true
	}
	name = sf.Name
	if tag != "" {
		parts := strings.Split(tag, ",")
		if parts[0] != "" {
			name = parts[0]
		}
		for _, p := range parts[1:] {
			if p == "required" {
				required = true
			}
		}
	}
	return name, required, false
}

func (s *schema) buildTable() {
	n := 1
	need := len(s.fields) * 2
	if need < 8 {
		need = 8
	}
	for n < need {
		n <<= 1
	}
	s.table = make([]hashEntry, n)
	mask := uint64(n - 1)
	for i := range s.fields {
		h := s.fields[i].hash
		pos := int(h & mask)
		for s.table[pos].used {
			pos = (pos + 1) & int(mask)
		}
		s.table[pos] = hashEntry{hash: h, index: i, used: true}
	}
	if len(s.fields) > 0 && len(s.fields) <= 32 {
		s.buildSmallLookup()
	}
}

func (s *schema) buildSmallLookup() {
	for i := range s.fields {
		sig := keySignature(s.fields[i].name)
		found := false
		for j := range s.smallLookup {
			if s.smallLookup[j].sig == sig {
				s.smallLookup[j].indices = append(s.smallLookup[j].indices, i)
				found = true
				break
			}
		}
		if !found {
			s.smallLookup = append(s.smallLookup, smallLookupEntry{sig: sig, indices: []int{i}})
		}
	}
}

func keySignature(key []byte) uint32 {
	if len(key) == 0 {
		return 0
	}
	return uint32(len(key))<<16 | uint32(key[0])<<8 | uint32(key[len(key)-1])
}

func (s *schema) lookupField(key []byte) *fieldMeta {
	if len(s.smallLookup) > 0 {
		sig := keySignature(key)
		for i := range s.smallLookup {
			e := &s.smallLookup[i]
			if e.sig != sig {
				continue
			}
			for _, idx := range e.indices {
				f := &s.fields[idx]
				if bytesEqual(f.name, key) {
					return f
				}
			}
			return nil
		}
		return nil
	}
	return s.lookupHash(xxhash.Sum64(key), key)
}

func (s *schema) lookupHash(hash uint64, key []byte) *fieldMeta {
	if len(s.table) == 0 {
		return nil
	}
	mask := uint64(len(s.table) - 1)
	pos := int(hash & mask)
	for {
		e := s.table[pos]
		if !e.used {
			return nil
		}
		if e.hash == hash {
			f := &s.fields[e.index]
			if bytesEqual(f.name, key) {
				return f
			}
		}
		pos = (pos + 1) & int(mask)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// escapeASCII is a 256-byte lookup table indexed by raw byte. It is non-zero
// for any byte that ends or interrupts a "simple" JSON string scan: the
// closing double quote, the start of an escape sequence '\\', any control
// character below 0x20, or any high byte (>= 0x80) that may begin a
// multi-byte UTF-8 sequence. Using all 256 entries lets the hot loop drop
// the explicit "is this byte ASCII?" branch and reduce per-byte work to a
// single indexed load and a zero comparison.
var escapeASCII = func() (a [256]uint8) {
	for c := 0; c < 256; c++ {
		if c < 0x20 || c >= 0x80 || c == '"' || c == '\\' {
			a[c] = 1
		}
	}
	return a
}()

// consumeSimpleString is the inlinable fast path for parsing a JSON string
// containing only ordinary ASCII bytes (no escapes, no control characters,
// no high bytes). It returns the number of bytes consumed including both
// surrounding quotes, or 0 if the input is not a simple string and the full
// scanner must be used. The function is intentionally small so the Go
// compiler will inline it into its callers; this matches the design of
// encoding/json/v2's jsonwire.ConsumeSimpleString and is what closes most
// of the gap on string-heavy payloads.
func consumeSimpleString(b []byte) (n int) {
	if len(b) > 0 && b[0] == '"' {
		n++
		for uint(len(b)) > uint(n) && escapeASCII[b[n]] == 0 {
			n++
		}
		if uint(len(b)) > uint(n) && b[n] == '"' {
			n++
			return n
		}
	}
	return 0
}

type parser struct {
	buf     []byte
	i       int
	n       int
	scratch []byte
	mutable bool
	opts    DecoderOptions
}

func (p *parser) skipWS() {
	i := p.i
	b := p.buf
	n := p.n
	for i < n {
		switch b[i] {
		case ' ', '\n', '\r', '\t':
			i++
		default:
			p.i = i
			return
		}
	}
	p.i = i
}

func (p *parser) peekKind() JSONKind {
	p.skipWS()
	if p.i >= p.n {
		return KindInvalid
	}
	switch p.buf[p.i] {
	case 'n':
		return KindNull
	case '{':
		return KindObject
	case '[':
		return KindArray
	case '"':
		return KindString
	case 't', 'f':
		return KindBool
	default:
		if p.buf[p.i] == '-' || (p.buf[p.i] >= '0' && p.buf[p.i] <= '9') {
			return KindNumber
		}
		return KindInvalid
	}
}

func checkMaxBytes(opts DecoderOptions, n int, off int) error {
	if opts.MaxBytes > 0 && n > opts.MaxBytes {
		return Error{Code: ErrValueTooLarge, Offset: off}
	}
	return nil
}

func (p *parser) hasStructuralLimits() bool {
	return p.opts.MaxDepth > 0 || p.opts.MaxObjectFields > 0 || p.opts.MaxArrayLength > 0
}

func pathField(name []byte) string {
	if len(name) == 0 {
		return ""
	}
	if isIdentPath(name) {
		return string(name)
	}
	return "[" + strconv.Quote(string(name)) + "]"
}

func isIdentPath(name []byte) bool {
	for i, c := range name {
		if i == 0 {
			if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_') {
				return false
			}
			continue
		}
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

func pathIndex(i int) string {
	return "[" + strconv.Itoa(i) + "]"
}

func joinPath(prefix, suffix string) string {
	if prefix == "" {
		return suffix
	}
	if suffix == "" {
		return prefix
	}
	if strings.HasPrefix(suffix, "[") {
		return prefix + suffix
	}
	return prefix + "." + suffix
}

func withPath(err error, prefix string) error {
	if err == nil || prefix == "" {
		return err
	}
	if e, ok := err.(Error); ok {
		e.Path = joinPath(prefix, e.Path)
		return e
	}
	return err
}

func (p *parser) decodeStruct(s *schema, base unsafe.Pointer) error {
	p.skipWS()
	if p.tryNull() {
		return Error{Code: ErrExpectedObject, Offset: p.i - 4}
	}
	if p.i >= p.n {
		return Error{Code: ErrUnexpectedEOF, Offset: p.i}
	}
	if p.buf[p.i] != '{' {
		return Error{Code: ErrExpectedObject, Offset: p.i}
	}
	p.resetSpecialFields(s, base)
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == '}' {
		p.i++
		if s.requiredMask != 0 {
			return missingRequiredError(s, 0, p.i)
		}
		return nil
	}

	var seen uint64
	for {
		p.skipWS()
		key, err := p.parseKey()
		if err != nil {
			return err
		}
		p.skipWS()
		if p.i >= p.n {
			return Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		if p.buf[p.i] != ':' {
			return Error{Code: ErrExpectedColon, Offset: p.i, Field: key, Path: pathField(key)}
		}
		p.i++
		p.skipWS()

		f := s.lookupField(key)
		if f == nil {
			if p.opts.DisallowUnknownFields {
				return Error{Code: ErrUnknownField, Offset: p.i, Field: key, Path: pathField(key)}
			}
			if err := p.skipValue(); err != nil {
				return withPath(err, pathField(key))
			}
		} else {
			if isForbiddenInfo(f.info) {
				return Error{Code: ErrForbiddenField, Offset: p.i, Field: f.name, Path: pathField(f.name)}
			}
			fieldPtr := unsafe.Add(base, f.offset)
			if f.decode != nil {
				if err := f.decode(p, fieldPtr); err != nil {
					return withPath(err, pathField(f.name))
				}
			} else if err := p.decodeInto(f.info, fieldPtr); err != nil {
				return withPath(err, pathField(f.name))
			}
			if f.required {
				seen |= uint64(1) << f.requiredIx
			}
		}

		p.skipWS()
		if p.i >= p.n {
			return Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		switch p.buf[p.i] {
		case ',':
			p.i++
			continue
		case '}':
			p.i++
			if (seen & s.requiredMask) != s.requiredMask {
				return missingRequiredError(s, seen, p.i)
			}
			return nil
		default:
			return Error{Code: ErrExpectedCommaOrEnd, Offset: p.i}
		}
	}
}

func (p *parser) resetSpecialFields(s *schema, base unsafe.Pointer) {
	for _, idx := range s.resetFields {
		f := &s.fields[idx]
		if f.info.zero != nil {
			f.info.zero(unsafe.Add(base, f.offset))
		}
	}
}

func isForbiddenInfo(ti *typeInfo) bool {
	return ti.kind == kindForbidden || (ti.kind == kindPtr && ti.elem != nil && ti.elem.kind == kindForbidden)
}

func missingRequiredError(s *schema, seen uint64, off int) error {
	for i := range s.fields {
		f := &s.fields[i]
		if f.required && (seen&(uint64(1)<<f.requiredIx)) == 0 {
			return Error{Code: ErrRequiredFieldMissing, Offset: off, Field: f.name, Path: pathField(f.name)}
		}
	}
	return Error{Code: ErrRequiredFieldMissing, Offset: off}
}

func (p *parser) parseKey() ([]byte, error) {
	if p.i >= p.n {
		return nil, Error{Code: ErrUnexpectedEOF, Offset: p.i}
	}
	if p.buf[p.i] != '"' {
		return nil, Error{Code: ErrExpectedString, Offset: p.i}
	}
	return p.parseStringToScratchOrInput()
}

func (p *parser) decodeInto(ti *typeInfo, ptr unsafe.Pointer) error {
	if ti.decode != nil {
		return ti.decode(p, ptr)
	}
	switch ti.kind {
	case kindBool:
		v, err := p.parseBoolOrNull(false)
		if err != nil {
			return err
		}
		*(*bool)(ptr) = v
		return nil
	case kindInt:
		v, err := p.parseInt64Bits(intBits())
		if err != nil {
			return err
		}
		*(*int)(ptr) = int(v)
		return nil
	case kindInt8:
		v, err := p.parseInt64Bits(8)
		if err != nil {
			return err
		}
		*(*int8)(ptr) = int8(v)
		return nil
	case kindInt16:
		v, err := p.parseInt64Bits(16)
		if err != nil {
			return err
		}
		*(*int16)(ptr) = int16(v)
		return nil
	case kindInt32:
		v, err := p.parseInt64Bits(32)
		if err != nil {
			return err
		}
		*(*int32)(ptr) = int32(v)
		return nil
	case kindInt64:
		v, err := p.parseInt64Bits(64)
		if err != nil {
			return err
		}
		*(*int64)(ptr) = v
		return nil
	case kindUint:
		v, err := p.parseUint64Bits(uintBits())
		if err != nil {
			return err
		}
		*(*uint)(ptr) = uint(v)
		return nil
	case kindUint8:
		v, err := p.parseUint64Bits(8)
		if err != nil {
			return err
		}
		*(*uint8)(ptr) = uint8(v)
		return nil
	case kindUint16:
		v, err := p.parseUint64Bits(16)
		if err != nil {
			return err
		}
		*(*uint16)(ptr) = uint16(v)
		return nil
	case kindUint32:
		v, err := p.parseUint64Bits(32)
		if err != nil {
			return err
		}
		*(*uint32)(ptr) = uint32(v)
		return nil
	case kindUint64:
		v, err := p.parseUint64Bits(64)
		if err != nil {
			return err
		}
		*(*uint64)(ptr) = v
		return nil
	case kindFloat32:
		v, err := p.parseFloat32()
		if err != nil {
			return err
		}
		*(*float32)(ptr) = v
		return nil
	case kindFloat64:
		v, err := p.parseFloat64()
		if err != nil {
			return err
		}
		*(*float64)(ptr) = v
		return nil
	case kindString:
		return p.decodeStringValue(ti, ptr)
	case kindBytes:
		return p.decodeBytesValue(ptr)
	case kindStruct:
		return p.decodeStruct(ti.schema, ptr)
	case kindPtr:
		return p.decodePtr(ti, ptr)
	case kindSlice:
		return p.decodeSlice(ti, ptr)
	case kindArray:
		return p.decodeArray(ti, ptr)
	case kindMap:
		return p.decodeMap(ti, ptr)
	case kindAny:
		v, err := p.parseAny()
		if err != nil {
			return err
		}
		*(*interface{})(ptr) = v
		return nil
	case kindTime:
		return p.decodeTime(ptr)
	case kindJSONNumber:
		return p.decodeJSONNumberValue(ptr)
	case kindRawValue:
		return p.decodeRaw(ti, ptr, KindInvalid)
	case kindRawObject:
		return p.decodeRaw(ti, ptr, KindObject)
	case kindRawArray:
		return p.decodeRaw(ti, ptr, KindArray)
	case kindOptional:
		return p.decodeOptional(ti, ptr)
	case kindNullable:
		return p.decodeNullable(ti, ptr)
	case kindOptionalNullable:
		return p.decodeOptionalNullable(ti, ptr)
	case kindRawUnion:
		return p.decodeRawUnion(ti, ptr)
	case kindPresent:
		return p.decodePresent(ti, ptr)
	case kindForbidden:
		return Error{Code: ErrForbiddenField, Offset: p.i}
	case kindStringOrSlice:
		return p.decodeStringOrSlice(ti, ptr)
	case kindStringOrObject:
		return p.decodeStringOrObject(ti, ptr)
	case kindJSONUnmarshaler:
		return p.decodeJSONUnmarshaler(ti, ptr)
	case kindTextUnmarshaler:
		return p.decodeTextUnmarshaler(ti, ptr)
	default:
		return Error{Code: ErrUnsupportedType, Offset: p.i}
	}
}

func ensureDecoder(ti *typeInfo) {
	seenTypes := map[*typeInfo]bool{}
	seenSchemas := map[*schema]bool{}
	ensureDecoderVisit(ti, seenTypes, seenSchemas)
	computeRetainsBufferRefs(ti, map[*typeInfo]bool{}, map[*schema]bool{})
}

func ensureDecoderVisit(ti *typeInfo, seenTypes map[*typeInfo]bool, seenSchemas map[*schema]bool) {
	if ti == nil || seenTypes[ti] {
		return
	}
	seenTypes[ti] = true
	if ti.decode == nil {
		ti.decode = makeTypeDecoder(ti)
	}
	ensureDecoderVisit(ti.elem, seenTypes, seenSchemas)
	ensureDecoderVisit(ti.alt, seenTypes, seenSchemas)
	if ti.schema != nil {
		if seenSchemas[ti.schema] {
			return
		}
		seenSchemas[ti.schema] = true
		for i := range ti.schema.fields {
			f := &ti.schema.fields[i]
			ensureDecoderVisit(f.info, seenTypes, seenSchemas)
			f.decode = f.info.decode
		}
	}
}

func computeRetainsBufferRefs(ti *typeInfo, seenTypes map[*typeInfo]bool, seenSchemas map[*schema]bool) bool {
	if ti == nil {
		return false
	}
	if ti.retainsBufferRefs {
		return true
	}
	if seenTypes[ti] {
		return false
	}
	seenTypes[ti] = true

	retains := false
	switch ti.kind {
	case kindString, kindBytes, kindAny, kindJSONNumber,
		kindRawValue, kindRawObject, kindRawArray, kindRawUnion,
		kindStringOrSlice, kindStringOrObject:
		retains = true
	case kindMap:
		// All supported maps have string keys, and map keys are retained.
		retains = true
	case kindPtr, kindSlice, kindArray, kindOptional, kindNullable, kindOptionalNullable:
		retains = computeRetainsBufferRefs(ti.elem, seenTypes, seenSchemas)
	}
	if !retains && ti.alt != nil {
		retains = computeRetainsBufferRefs(ti.alt, seenTypes, seenSchemas)
	}
	if !retains && ti.schema != nil && !seenSchemas[ti.schema] {
		seenSchemas[ti.schema] = true
		for i := range ti.schema.fields {
			if computeRetainsBufferRefs(ti.schema.fields[i].info, seenTypes, seenSchemas) {
				retains = true
				break
			}
		}
	}
	ti.retainsBufferRefs = retains
	return retains
}

func makeTypeDecoder(ti *typeInfo) decoderFunc {
	switch ti.kind {
	case kindBool:
		return func(p *parser, ptr unsafe.Pointer) error {
			v, err := p.parseBoolOrNull(false)
			if err != nil {
				return err
			}
			*(*bool)(ptr) = v
			return nil
		}
	case kindInt:
		return func(p *parser, ptr unsafe.Pointer) error {
			v, err := p.parseInt64Bits(intBits())
			if err != nil {
				return err
			}
			*(*int)(ptr) = int(v)
			return nil
		}
	case kindInt8:
		return func(p *parser, ptr unsafe.Pointer) error {
			v, err := p.parseInt64Bits(8)
			if err != nil {
				return err
			}
			*(*int8)(ptr) = int8(v)
			return nil
		}
	case kindInt16:
		return func(p *parser, ptr unsafe.Pointer) error {
			v, err := p.parseInt64Bits(16)
			if err != nil {
				return err
			}
			*(*int16)(ptr) = int16(v)
			return nil
		}
	case kindInt32:
		return func(p *parser, ptr unsafe.Pointer) error {
			v, err := p.parseInt64Bits(32)
			if err != nil {
				return err
			}
			*(*int32)(ptr) = int32(v)
			return nil
		}
	case kindInt64:
		return func(p *parser, ptr unsafe.Pointer) error {
			v, err := p.parseInt64Bits(64)
			if err != nil {
				return err
			}
			*(*int64)(ptr) = v
			return nil
		}
	case kindUint:
		return func(p *parser, ptr unsafe.Pointer) error {
			v, err := p.parseUint64Bits(uintBits())
			if err != nil {
				return err
			}
			*(*uint)(ptr) = uint(v)
			return nil
		}
	case kindUint8:
		return func(p *parser, ptr unsafe.Pointer) error {
			v, err := p.parseUint64Bits(8)
			if err != nil {
				return err
			}
			*(*uint8)(ptr) = uint8(v)
			return nil
		}
	case kindUint16:
		return func(p *parser, ptr unsafe.Pointer) error {
			v, err := p.parseUint64Bits(16)
			if err != nil {
				return err
			}
			*(*uint16)(ptr) = uint16(v)
			return nil
		}
	case kindUint32:
		return func(p *parser, ptr unsafe.Pointer) error {
			v, err := p.parseUint64Bits(32)
			if err != nil {
				return err
			}
			*(*uint32)(ptr) = uint32(v)
			return nil
		}
	case kindUint64:
		return func(p *parser, ptr unsafe.Pointer) error {
			v, err := p.parseUint64Bits(64)
			if err != nil {
				return err
			}
			*(*uint64)(ptr) = v
			return nil
		}
	case kindFloat32:
		return func(p *parser, ptr unsafe.Pointer) error {
			v, err := p.parseFloat32()
			if err != nil {
				return err
			}
			*(*float32)(ptr) = v
			return nil
		}
	case kindFloat64:
		return func(p *parser, ptr unsafe.Pointer) error {
			v, err := p.parseFloat64()
			if err != nil {
				return err
			}
			*(*float64)(ptr) = v
			return nil
		}
	case kindString:
		return func(p *parser, ptr unsafe.Pointer) error { return p.decodeStringValue(ti, ptr) }
	case kindBytes:
		return func(p *parser, ptr unsafe.Pointer) error { return p.decodeBytesValue(ptr) }
	case kindStruct:
		return func(p *parser, ptr unsafe.Pointer) error { return p.decodeStruct(ti.schema, ptr) }
	case kindPtr:
		return func(p *parser, ptr unsafe.Pointer) error { return p.decodePtr(ti, ptr) }
	case kindSlice:
		return func(p *parser, ptr unsafe.Pointer) error { return p.decodeSlice(ti, ptr) }
	case kindArray:
		return func(p *parser, ptr unsafe.Pointer) error { return p.decodeArray(ti, ptr) }
	case kindMap:
		return func(p *parser, ptr unsafe.Pointer) error { return p.decodeMap(ti, ptr) }
	case kindAny:
		return func(p *parser, ptr unsafe.Pointer) error {
			v, err := p.parseAny()
			if err != nil {
				return err
			}
			*(*interface{})(ptr) = v
			return nil
		}
	case kindTime:
		return func(p *parser, ptr unsafe.Pointer) error { return p.decodeTime(ptr) }
	case kindJSONNumber:
		return func(p *parser, ptr unsafe.Pointer) error { return p.decodeJSONNumberValue(ptr) }
	case kindRawValue:
		return func(p *parser, ptr unsafe.Pointer) error { return p.decodeRaw(ti, ptr, KindInvalid) }
	case kindRawObject:
		return func(p *parser, ptr unsafe.Pointer) error { return p.decodeRaw(ti, ptr, KindObject) }
	case kindRawArray:
		return func(p *parser, ptr unsafe.Pointer) error { return p.decodeRaw(ti, ptr, KindArray) }
	case kindOptional:
		return func(p *parser, ptr unsafe.Pointer) error { return p.decodeOptional(ti, ptr) }
	case kindNullable:
		return func(p *parser, ptr unsafe.Pointer) error { return p.decodeNullable(ti, ptr) }
	case kindOptionalNullable:
		return func(p *parser, ptr unsafe.Pointer) error { return p.decodeOptionalNullable(ti, ptr) }
	case kindRawUnion:
		return func(p *parser, ptr unsafe.Pointer) error { return p.decodeRawUnion(ti, ptr) }
	case kindPresent:
		return func(p *parser, ptr unsafe.Pointer) error { return p.decodePresent(ti, ptr) }
	case kindForbidden:
		return func(p *parser, ptr unsafe.Pointer) error { return Error{Code: ErrForbiddenField, Offset: p.i} }
	case kindStringOrSlice:
		return func(p *parser, ptr unsafe.Pointer) error { return p.decodeStringOrSlice(ti, ptr) }
	case kindStringOrObject:
		return func(p *parser, ptr unsafe.Pointer) error { return p.decodeStringOrObject(ti, ptr) }
	case kindJSONUnmarshaler:
		return func(p *parser, ptr unsafe.Pointer) error { return p.decodeJSONUnmarshaler(ti, ptr) }
	case kindTextUnmarshaler:
		return func(p *parser, ptr unsafe.Pointer) error { return p.decodeTextUnmarshaler(ti, ptr) }
	default:
		return func(p *parser, ptr unsafe.Pointer) error { return Error{Code: ErrUnsupportedType, Offset: p.i} }
	}
}

func intBits() int {
	return 32 << (^uint(0) >> 63)
}

func uintBits() int {
	return intBits()
}

func setString(_ reflect.Type, ptr unsafe.Pointer, v string) {
	*(*string)(ptr) = v
}

func (p *parser) ownString(b []byte) string {
	return unsafeBytesToString(b)
}

func setOwnedBytes(ptr unsafe.Pointer, b []byte) {
	dst := (*[]byte)(ptr)
	if len(b) == 0 {
		if *dst != nil {
			*dst = (*dst)[:0]
		} else {
			*dst = nil
		}
		return
	}
	*dst = b[:len(b):len(b)]
}

func (p *parser) decodeStringValue(ti *typeInfo, ptr unsafe.Pointer) error {
	b, err := p.parseStringFully()
	if err != nil {
		return err
	}
	setString(ti.typ, ptr, p.ownString(b))
	return nil
}

func (p *parser) decodeBytesValue(ptr unsafe.Pointer) error {
	b, err := p.parseStringFully()
	if err != nil {
		return err
	}
	setOwnedBytes(ptr, b)
	return nil
}

func (p *parser) decodeJSONNumberValue(ptr unsafe.Pointer) error {
	b, err := p.parseNumberBytes()
	if err != nil {
		return err
	}
	*(*json.Number)(ptr) = json.Number(p.ownString(b))
	return nil
}

func (p *parser) decodePtr(ti *typeInfo, ptr unsafe.Pointer) error {
	p.skipWS()
	if p.tryNull() {
		*(*unsafe.Pointer)(ptr) = nil
		return nil
	}
	pp := (*unsafe.Pointer)(ptr)
	if *pp == nil {
		*pp = ti.alloc()
	}
	return p.decodeInto(ti.elem, *pp)
}

func (p *parser) decodeTime(ptr unsafe.Pointer) error {
	p.skipWS()
	if p.tryNull() {
		*(*time.Time)(ptr) = time.Time{}
		return nil
	}
	b, err := p.parseStringFully()
	if err != nil {
		return err
	}
	v, err := time.Parse(time.RFC3339Nano, unsafeBytesToString(b))
	if err != nil {
		return Error{Code: ErrInvalidString, Offset: p.i}
	}
	*(*time.Time)(ptr) = v
	return nil
}

func (p *parser) decodeJSONUnmarshaler(ti *typeInfo, ptr unsafe.Pointer) error {
	p.skipWS()
	start := p.i
	if err := p.skipValue(); err != nil {
		return err
	}
	raw := p.buf[start:p.i]
	v := reflect.NewAt(ti.typ, ptr)
	if u, ok := v.Interface().(json.Unmarshaler); ok {
		return u.UnmarshalJSON(raw)
	}
	if v.Elem().CanInterface() {
		if u, ok := v.Elem().Interface().(json.Unmarshaler); ok {
			return u.UnmarshalJSON(raw)
		}
	}
	return Error{Code: ErrUnsupportedType, Offset: start}
}

func (p *parser) decodeTextUnmarshaler(ti *typeInfo, ptr unsafe.Pointer) error {
	p.skipWS()
	if p.tryNull() {
		reflect.NewAt(ti.typ, ptr).Elem().SetZero()
		return nil
	}
	b, err := p.parseStringFully()
	if err != nil {
		return err
	}
	v := reflect.NewAt(ti.typ, ptr)
	if u, ok := v.Interface().(encoding.TextUnmarshaler); ok {
		return u.UnmarshalText(b)
	}
	if v.Elem().CanInterface() {
		if u, ok := v.Elem().Interface().(encoding.TextUnmarshaler); ok {
			return u.UnmarshalText(b)
		}
	}
	return Error{Code: ErrUnsupportedType, Offset: p.i}
}

func (p *parser) decodeRaw(ti *typeInfo, ptr unsafe.Pointer, want JSONKind) error {
	p.skipWS()
	start := p.i
	k := p.peekKind()
	if want == KindObject && k != KindObject && k != KindNull {
		return Error{Code: ErrExpectedObject, Offset: p.i}
	}
	if want == KindArray && k != KindArray && k != KindNull {
		return Error{Code: ErrExpectedArray, Offset: p.i}
	}
	if err := p.skipValue(); err != nil {
		return err
	}
	if err := checkMaxBytes(p.opts, p.i-start, start); err != nil {
		return err
	}
	setRawBytes(ti, ptr, p.buf[start:p.i])
	*(*bool)(unsafe.Add(ptr, ti.presentOffset)) = true
	return nil
}

func (p *parser) decodeRawUnion(ti *typeInfo, ptr unsafe.Pointer) error {
	p.skipWS()
	start := p.i
	k := p.peekKind()
	if k == KindInvalid {
		return Error{Code: ErrInvalidLiteral, Offset: p.i}
	}
	if err := p.skipValue(); err != nil {
		return err
	}
	if err := checkMaxBytes(p.opts, p.i-start, start); err != nil {
		return err
	}
	setRawBytes(ti, ptr, p.buf[start:p.i])
	*(*JSONKind)(unsafe.Add(ptr, ti.kindOffset)) = k
	return nil
}

func (p *parser) decodePresent(ti *typeInfo, ptr unsafe.Pointer) error {
	ti.zero(ptr)
	*(*bool)(unsafe.Add(ptr, ti.presentOffset)) = true
	p.skipWS()
	if p.tryNull() {
		*(*bool)(unsafe.Add(ptr, ti.nullOffset)) = true
		return nil
	}
	return p.skipValue()
}

func setRawBytes(ti *typeInfo, ptr unsafe.Pointer, raw []byte) {
	dst := (*[]byte)(unsafe.Add(ptr, ti.bytesOffset))
	if len(raw) == 0 {
		if *dst != nil {
			*dst = (*dst)[:0]
		} else {
			*dst = nil
		}
		return
	}
	*dst = raw[:len(raw):len(raw)]
}

func (p *parser) decodeOptional(ti *typeInfo, ptr unsafe.Pointer) error {
	ti.zero(ptr)
	*(*bool)(unsafe.Add(ptr, ti.presentOffset)) = true
	return p.decodeInto(ti.elem, unsafe.Add(ptr, ti.valueOffset))
}

func (p *parser) decodeNullable(ti *typeInfo, ptr unsafe.Pointer) error {
	ti.zero(ptr)
	p.skipWS()
	if p.tryNull() {
		*(*bool)(unsafe.Add(ptr, ti.nullOffset)) = true
		return nil
	}
	return p.decodeInto(ti.elem, unsafe.Add(ptr, ti.valueOffset))
}

func (p *parser) decodeOptionalNullable(ti *typeInfo, ptr unsafe.Pointer) error {
	ti.zero(ptr)
	*(*bool)(unsafe.Add(ptr, ti.presentOffset)) = true
	p.skipWS()
	if p.tryNull() {
		*(*bool)(unsafe.Add(ptr, ti.nullOffset)) = true
		return nil
	}
	return p.decodeInto(ti.elem, unsafe.Add(ptr, ti.valueOffset))
}

func (p *parser) decodeStringOrSlice(ti *typeInfo, ptr unsafe.Pointer) error {
	ti.zero(ptr)
	p.skipWS()
	switch p.peekKind() {
	case KindString:
		b, err := p.parseStringFully()
		if err != nil {
			return err
		}
		*(*bool)(unsafe.Add(ptr, ti.isStringOffset)) = true
		*(*string)(unsafe.Add(ptr, ti.stringOffset)) = p.ownString(b)
		return nil
	case KindArray:
		return p.decodeInto(ti.alt, unsafe.Add(ptr, ti.sliceOffset))
	default:
		return Error{Code: ErrExpectedStringOrArray, Offset: p.i}
	}
}

func (p *parser) decodeStringOrObject(ti *typeInfo, ptr unsafe.Pointer) error {
	ti.zero(ptr)
	p.skipWS()
	switch p.peekKind() {
	case KindString:
		b, err := p.parseStringFully()
		if err != nil {
			return err
		}
		*(*bool)(unsafe.Add(ptr, ti.isStringOffset)) = true
		*(*string)(unsafe.Add(ptr, ti.stringOffset)) = p.ownString(b)
		return nil
	case KindObject:
		return p.decodeInto(ti.alt, unsafe.Add(ptr, ti.objectOffset))
	default:
		return Error{Code: ErrExpectedStringOrObject, Offset: p.i}
	}
}

func (p *parser) parseStringFully() ([]byte, error) {
	b, _, err := p.parseStringMaybeAlias()
	return b, err
}

// parseStringToScratchOrInput parses a JSON string starting at p.buf[p.i].
// On success, p.i advances past the closing quote. The returned byte slice
// aliases p.buf for unescaped strings. Escaped strings are compacted in place
// into p.buf when p.mutable is true; otherwise they are decoded into p.scratch.
func (p *parser) parseStringToScratchOrInput() ([]byte, error) {
	b, _, err := p.parseStringMaybeAlias()
	return b, err
}

// parseStringMaybeAlias parses a JSON string and reports whether the returned
// bytes alias p.buf. If p.mutable is true, escaped strings are destructively
// compacted in place and also alias p.buf. If p.mutable is false, escaped
// strings are decoded into p.scratch and fromInput is false.
func (p *parser) parseStringMaybeAlias() (b []byte, fromInput bool, err error) {
	if n := consumeSimpleString(p.buf[p.i:]); n > 0 {
		out := p.buf[p.i+1 : p.i+n-1]
		p.i += n
		return out, true, nil
	}
	return p.parseStringSlowMaybeAlias()
}

func (p *parser) parseStringSlow() ([]byte, error) {
	b, _, err := p.parseStringSlowMaybeAlias()
	return b, err
}

// parseStringSlowMaybeAlias is the full string scanner used when the fast path
// cannot handle the input. It returns fromInput=true for no-escape strings,
// including non-ASCII strings that validate as UTF-8. For escaped strings, it
// returns fromInput=true when p.mutable allows in-place compaction and false
// when decoding falls back to p.scratch.
func (p *parser) parseStringSlowMaybeAlias() ([]byte, bool, error) {
	if p.i >= p.n || p.buf[p.i] != '"' {
		return nil, false, Error{Code: ErrExpectedString, Offset: p.i}
	}
	startQuote := p.i
	i := p.i + 1
	start := i
	b := p.buf
	n := p.n
	high := false
	for i < n {
		c := b[i]
		if c == '"' {
			out := b[start:i]
			if high && !utf8.Valid(out) {
				return nil, false, Error{Code: ErrInvalidString, Offset: start}
			}
			p.i = i + 1
			return out, true, nil
		}
		if c == '\\' {
			return p.parseEscapedString(startQuote)
		}
		if c < 0x20 {
			return nil, false, Error{Code: ErrInvalidString, Offset: i}
		}
		if c >= 0x80 {
			high = true
		}
		i++
	}
	return nil, false, Error{Code: ErrUnexpectedEOF, Offset: i}
}

func (p *parser) parseEscapedString(startQuote int) ([]byte, bool, error) {
	if p.mutable {
		out, err := p.parseEscapedStringInPlace(startQuote)
		return out, true, err
	}
	out, err := p.parseEscapedStringScratch(startQuote)
	return out, false, err
}

func (p *parser) parseEscapedStringInPlace(startQuote int) ([]byte, error) {
	b := p.buf
	n := p.n
	i := startQuote + 1
	outStart := i
	out := outStart
	for i < n {
		c := b[i]
		switch c {
		case '"':
			decoded := b[outStart:out]
			if !utf8.Valid(decoded) {
				return nil, Error{Code: ErrInvalidString, Offset: startQuote}
			}
			p.i = i + 1
			return decoded, nil
		case '\\':
			i++
			if i >= n {
				return nil, Error{Code: ErrUnexpectedEOF, Offset: i}
			}
			esc := b[i]
			switch esc {
			case '"', '\\', '/':
				b[out] = esc
				out++
				i++
			case 'b':
				b[out] = '\b'
				out++
				i++
			case 'f':
				b[out] = '\f'
				out++
				i++
			case 'n':
				b[out] = '\n'
				out++
				i++
			case 'r':
				b[out] = '\r'
				out++
				i++
			case 't':
				b[out] = '\t'
				out++
				i++
			case 'u':
				r, ni, err := p.parseUnicodeEscape(i + 1)
				if err != nil {
					return nil, err
				}
				out = writeRuneUTF8(b, out, r)
				i = ni
			default:
				return nil, Error{Code: ErrInvalidEscape, Offset: i}
			}
		default:
			if c < 0x20 {
				return nil, Error{Code: ErrInvalidString, Offset: i}
			}
			b[out] = c
			out++
			i++
		}
	}
	return nil, Error{Code: ErrUnexpectedEOF, Offset: i}
}

func (p *parser) parseEscapedStringScratch(startQuote int) ([]byte, error) {
	b := p.buf
	n := p.n
	p.scratch = p.scratch[:0]
	i := startQuote + 1
	chunkStart := i
	for i < n {
		c := b[i]
		switch c {
		case '"':
			p.scratch = append(p.scratch, b[chunkStart:i]...)
			if !utf8.Valid(p.scratch) {
				return nil, Error{Code: ErrInvalidString, Offset: startQuote}
			}
			p.i = i + 1
			return p.scratch, nil
		case '\\':
			p.scratch = append(p.scratch, b[chunkStart:i]...)
			i++
			if i >= n {
				return nil, Error{Code: ErrUnexpectedEOF, Offset: i}
			}
			esc := b[i]
			switch esc {
			case '"', '\\', '/':
				p.scratch = append(p.scratch, esc)
				i++
			case 'b':
				p.scratch = append(p.scratch, '\b')
				i++
			case 'f':
				p.scratch = append(p.scratch, '\f')
				i++
			case 'n':
				p.scratch = append(p.scratch, '\n')
				i++
			case 'r':
				p.scratch = append(p.scratch, '\r')
				i++
			case 't':
				p.scratch = append(p.scratch, '\t')
				i++
			case 'u':
				r, ni, err := p.parseUnicodeEscape(i + 1)
				if err != nil {
					return nil, err
				}
				p.scratch = appendRuneUTF8(p.scratch, r)
				i = ni
			default:
				return nil, Error{Code: ErrInvalidEscape, Offset: i}
			}
			chunkStart = i
		default:
			if c < 0x20 {
				return nil, Error{Code: ErrInvalidString, Offset: i}
			}
			i++
		}
	}
	return nil, Error{Code: ErrUnexpectedEOF, Offset: i}
}

func (p *parser) parseUnicodeEscape(hexStart int) (rune, int, error) {
	r1, ok := readHex4(p.buf, hexStart, p.n)
	if !ok {
		return 0, hexStart, Error{Code: ErrInvalidUnicodeEscape, Offset: hexStart}
	}
	i := hexStart + 4
	r := rune(r1)
	if utf16.IsSurrogate(r) {
		if r < 0xD800 || r > 0xDBFF {
			return 0, i, Error{Code: ErrInvalidUnicodeEscape, Offset: hexStart}
		}
		if i+6 > p.n || p.buf[i] != '\\' || p.buf[i+1] != 'u' {
			return 0, i, Error{Code: ErrInvalidUnicodeEscape, Offset: i}
		}
		r2, ok := readHex4(p.buf, i+2, p.n)
		if !ok {
			return 0, i + 2, Error{Code: ErrInvalidUnicodeEscape, Offset: i + 2}
		}
		rr2 := rune(r2)
		if rr2 < 0xDC00 || rr2 > 0xDFFF {
			return 0, i + 2, Error{Code: ErrInvalidUnicodeEscape, Offset: i + 2}
		}
		return utf16.DecodeRune(r, rr2), i + 6, nil
	}
	return r, i, nil
}

func readHex4(b []byte, i, n int) (uint16, bool) {
	if i+4 > n {
		return 0, false
	}
	var v uint16
	for j := 0; j < 4; j++ {
		c := b[i+j]
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, false
		}
		v = (v << 4) | uint16(d)
	}
	return v, true
}

func writeRuneUTF8(dst []byte, i int, r rune) int {
	return i + utf8.EncodeRune(dst[i:], r)
}

func appendRuneUTF8(dst []byte, r rune) []byte {
	switch {
	case r <= 0x7F:
		return append(dst, byte(r))
	case r <= 0x7FF:
		return append(dst, byte(0xC0|r>>6), byte(0x80|r&0x3F))
	case r <= 0xFFFF:
		return append(dst, byte(0xE0|r>>12), byte(0x80|(r>>6)&0x3F), byte(0x80|r&0x3F))
	default:
		return append(dst, byte(0xF0|r>>18), byte(0x80|(r>>12)&0x3F), byte(0x80|(r>>6)&0x3F), byte(0x80|r&0x3F))
	}
}

// skipString advances p.i past a JSON string. A tiny dispatcher: the
// inlinable consumeSimpleString fast path handles ordinary ASCII strings,
// and the full validating scanner runs only on inputs that the fast path
// rejects.
func (p *parser) skipString() error {
	if n := consumeSimpleString(p.buf[p.i:]); n > 0 {
		p.i += n
		return nil
	}
	return p.skipStringSlow()
}

func (p *parser) skipStringSlow() error {
	if p.i >= p.n || p.buf[p.i] != '"' {
		return Error{Code: ErrExpectedString, Offset: p.i}
	}
	b := p.buf
	n := p.n
	i := p.i + 1
	chunkStart := i
	high := false
	for i < n {
		c := b[i]
		switch c {
		case '"':
			if high && !utf8.Valid(b[chunkStart:i]) {
				return Error{Code: ErrInvalidString, Offset: chunkStart}
			}
			p.i = i + 1
			return nil
		case '\\':
			if high && !utf8.Valid(b[chunkStart:i]) {
				return Error{Code: ErrInvalidString, Offset: chunkStart}
			}
			high = false
			i++
			if i >= n {
				return Error{Code: ErrUnexpectedEOF, Offset: i}
			}
			switch b[i] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				i++
			case 'u':
				r1, ok := readHex4(b, i+1, n)
				if !ok {
					return Error{Code: ErrInvalidUnicodeEscape, Offset: i + 1}
				}
				i += 5
				r := rune(r1)
				if utf16.IsSurrogate(r) {
					if r < 0xD800 || r > 0xDBFF {
						return Error{Code: ErrInvalidUnicodeEscape, Offset: i - 4}
					}
					if i+6 > n || b[i] != '\\' || b[i+1] != 'u' {
						return Error{Code: ErrInvalidUnicodeEscape, Offset: i}
					}
					r2, ok := readHex4(b, i+2, n)
					if !ok {
						return Error{Code: ErrInvalidUnicodeEscape, Offset: i + 2}
					}
					rr2 := rune(r2)
					if rr2 < 0xDC00 || rr2 > 0xDFFF {
						return Error{Code: ErrInvalidUnicodeEscape, Offset: i + 2}
					}
					i += 6
				}
			default:
				return Error{Code: ErrInvalidEscape, Offset: i}
			}
			chunkStart = i
		case 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31:
			return Error{Code: ErrInvalidString, Offset: i}
		default:
			if c >= 0x80 {
				high = true
			}
			i++
		}
	}
	return Error{Code: ErrUnexpectedEOF, Offset: i}
}

func (p *parser) parseBoolOrNull(allowNull bool) (bool, error) {
	if p.i >= p.n {
		return false, Error{Code: ErrUnexpectedEOF, Offset: p.i}
	}
	switch p.buf[p.i] {
	case 't':
		if p.i+4 <= p.n && p.buf[p.i+1] == 'r' && p.buf[p.i+2] == 'u' && p.buf[p.i+3] == 'e' {
			p.i += 4
			return true, nil
		}
	case 'f':
		if p.i+5 <= p.n && p.buf[p.i+1] == 'a' && p.buf[p.i+2] == 'l' && p.buf[p.i+3] == 's' && p.buf[p.i+4] == 'e' {
			p.i += 5
			return false, nil
		}
	case 'n':
		if allowNull && p.tryNull() {
			return false, nil
		}
		return false, Error{Code: ErrInvalidNull, Offset: p.i}
	}
	return false, Error{Code: ErrInvalidLiteral, Offset: p.i}
}

func (p *parser) tryNull() bool {
	if p.i+4 <= p.n && p.buf[p.i] == 'n' && p.buf[p.i+1] == 'u' && p.buf[p.i+2] == 'l' && p.buf[p.i+3] == 'l' {
		p.i += 4
		return true
	}
	return false
}

func (p *parser) parseInt64Bits(bits int) (int64, error) {
	if p.i >= p.n {
		return 0, Error{Code: ErrUnexpectedEOF, Offset: p.i}
	}
	start := p.i
	neg := false
	if p.buf[p.i] == '-' {
		neg = true
		p.i++
		if p.i >= p.n {
			return 0, Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
	}
	if p.buf[p.i] < '0' || p.buf[p.i] > '9' {
		return 0, Error{Code: ErrInvalidNumber, Offset: p.i}
	}
	if p.buf[p.i] == '0' {
		p.i++
		if p.i < p.n && p.buf[p.i] >= '0' && p.buf[p.i] <= '9' {
			return 0, Error{Code: ErrInvalidNumber, Offset: p.i}
		}
	}
	var u uint64
	limit := uint64(math.MaxInt64)
	if neg {
		limit = uint64(math.MaxInt64) + 1
	}
	for p.i < p.n {
		c := p.buf[p.i]
		if c < '0' || c > '9' {
			break
		}
		d := uint64(c - '0')
		if u > (limit-d)/10 {
			return 0, Error{Code: ErrNumberOverflow, Offset: start}
		}
		u = u*10 + d
		p.i++
	}
	if !isValueEnd(p) {
		return 0, Error{Code: ErrInvalidNumber, Offset: p.i}
	}
	if neg {
		if u == uint64(math.MaxInt64)+1 {
			if bits < 64 {
				min := int64(-1) << (bits - 1)
				if math.MinInt64 < min {
					return 0, Error{Code: ErrNumberOverflow, Offset: start}
				}
			}
			return math.MinInt64, nil
		}
		v := -int64(u)
		if bits < 64 {
			min := int64(-1) << (bits - 1)
			if v < min {
				return 0, Error{Code: ErrNumberOverflow, Offset: start}
			}
		}
		return v, nil
	}
	v := int64(u)
	if bits < 64 {
		max := int64(1)<<(bits-1) - 1
		if v > max {
			return 0, Error{Code: ErrNumberOverflow, Offset: start}
		}
	}
	return v, nil
}

func (p *parser) parseUint64Bits(bits int) (uint64, error) {
	if p.i >= p.n {
		return 0, Error{Code: ErrUnexpectedEOF, Offset: p.i}
	}
	start := p.i
	if p.buf[p.i] == '-' {
		return 0, Error{Code: ErrInvalidNumber, Offset: p.i}
	}
	if p.buf[p.i] < '0' || p.buf[p.i] > '9' {
		return 0, Error{Code: ErrInvalidNumber, Offset: p.i}
	}
	if p.buf[p.i] == '0' {
		p.i++
		if p.i < p.n && p.buf[p.i] >= '0' && p.buf[p.i] <= '9' {
			return 0, Error{Code: ErrInvalidNumber, Offset: p.i}
		}
	}
	var limit uint64 = math.MaxUint64
	if bits < 64 {
		limit = uint64(1)<<bits - 1
	}
	var u uint64
	for p.i < p.n {
		c := p.buf[p.i]
		if c < '0' || c > '9' {
			break
		}
		d := uint64(c - '0')
		if u > (limit-d)/10 {
			return 0, Error{Code: ErrNumberOverflow, Offset: start}
		}
		u = u*10 + d
		p.i++
	}
	if !isValueEnd(p) {
		return 0, Error{Code: ErrInvalidNumber, Offset: p.i}
	}
	return u, nil
}

func isValueEnd(p *parser) bool {
	if p.i >= p.n {
		return true
	}
	switch p.buf[p.i] {
	case ' ', '\n', '\r', '\t', ',', '}', ']':
		return true
	default:
		return false
	}
}

func (p *parser) parseNumberBytes() ([]byte, error) {
	start := p.i
	if err := p.skipNumber(); err != nil {
		return nil, err
	}
	return p.buf[start:p.i], nil
}

type decimalFloat struct {
	neg       bool
	mant      uint64
	exp10     int
	truncated bool
}

var float64pow10 = [...]float64{
	1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7,
	1e8, 1e9, 1e10, 1e11, 1e12, 1e13, 1e14, 1e15,
	1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22,
}

var float32pow10 = [...]float32{
	1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7,
	1e8, 1e9, 1e10,
}

func (p *parser) parseFloat32() (float32, error) {
	start := p.i
	d, err := p.scanDecimalFloat()
	if err != nil {
		return 0, err
	}
	if v, ok := fastFloat32(d); ok {
		return v, nil
	}
	v, err := strconv.ParseFloat(unsafeBytesToString(p.buf[start:p.i]), 32)
	if err != nil {
		if numErr, ok := err.(*strconv.NumError); ok && numErr.Err == strconv.ErrRange {
			if math.IsInf(v, 0) {
				return 0, Error{Code: ErrNumberOverflow, Offset: start}
			}
			return float32(v), nil // underflow to zero is a valid finite result
		}
		return 0, Error{Code: ErrInvalidNumber, Offset: start}
	}
	if math.IsInf(v, 0) {
		return 0, Error{Code: ErrNumberOverflow, Offset: start}
	}
	return float32(v), nil
}

func (p *parser) parseFloat64() (float64, error) {
	start := p.i
	d, err := p.scanDecimalFloat()
	if err != nil {
		return 0, err
	}
	if v, ok := fastFloat64(d); ok {
		return v, nil
	}
	v, err := strconv.ParseFloat(unsafeBytesToString(p.buf[start:p.i]), 64)
	if err != nil {
		if numErr, ok := err.(*strconv.NumError); ok && numErr.Err == strconv.ErrRange {
			if math.IsInf(v, 0) {
				return 0, Error{Code: ErrNumberOverflow, Offset: start}
			}
			return v, nil // underflow to zero is a valid finite result
		}
		return 0, Error{Code: ErrInvalidNumber, Offset: start}
	}
	if math.IsInf(v, 0) {
		return 0, Error{Code: ErrNumberOverflow, Offset: start}
	}
	return v, nil
}

func (p *parser) scanDecimalFloat() (decimalFloat, error) {
	if p.i >= p.n {
		return decimalFloat{}, Error{Code: ErrUnexpectedEOF, Offset: p.i}
	}
	d := decimalFloat{}
	if p.buf[p.i] == '-' {
		d.neg = true
		p.i++
		if p.i >= p.n {
			return decimalFloat{}, Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
	}
	if p.buf[p.i] < '0' || p.buf[p.i] > '9' {
		return decimalFloat{}, Error{Code: ErrInvalidNumber, Offset: p.i}
	}

	mantDigits := 0
	sigDigits := 0
	fracDigits := 0
	seenSignificant := false
	consumeDigit := func(c byte, afterDecimal bool) {
		if afterDecimal {
			fracDigits++
		}
		if !seenSignificant {
			if c == '0' {
				return
			}
			seenSignificant = true
		}
		sigDigits++
		if mantDigits < 19 {
			d.mant = d.mant*10 + uint64(c-'0')
			mantDigits++
		} else {
			d.truncated = true
		}
	}

	if p.buf[p.i] == '0' {
		consumeDigit('0', false)
		p.i++
		if p.i < p.n && p.buf[p.i] >= '0' && p.buf[p.i] <= '9' {
			return decimalFloat{}, Error{Code: ErrInvalidNumber, Offset: p.i}
		}
	} else {
		for p.i < p.n {
			c := p.buf[p.i]
			if c < '0' || c > '9' {
				break
			}
			consumeDigit(c, false)
			p.i++
		}
	}

	if p.i < p.n && p.buf[p.i] == '.' {
		p.i++
		if p.i >= p.n || p.buf[p.i] < '0' || p.buf[p.i] > '9' {
			return decimalFloat{}, Error{Code: ErrInvalidNumber, Offset: p.i}
		}
		for p.i < p.n {
			c := p.buf[p.i]
			if c < '0' || c > '9' {
				break
			}
			consumeDigit(c, true)
			p.i++
		}
	}

	expPart := 0
	if p.i < p.n && (p.buf[p.i] == 'e' || p.buf[p.i] == 'E') {
		p.i++
		expNeg := false
		if p.i < p.n && (p.buf[p.i] == '+' || p.buf[p.i] == '-') {
			expNeg = p.buf[p.i] == '-'
			p.i++
		}
		if p.i >= p.n || p.buf[p.i] < '0' || p.buf[p.i] > '9' {
			return decimalFloat{}, Error{Code: ErrInvalidNumber, Offset: p.i}
		}
		for p.i < p.n {
			c := p.buf[p.i]
			if c < '0' || c > '9' {
				break
			}
			if expPart < 1000000 {
				expPart = expPart*10 + int(c-'0')
			}
			p.i++
		}
		if expNeg {
			expPart = -expPart
		}
	}
	if !isValueEnd(p) {
		return decimalFloat{}, Error{Code: ErrInvalidNumber, Offset: p.i}
	}
	if d.mant != 0 {
		d.exp10 = expPart - fracDigits + (sigDigits - mantDigits)
	} else {
		d.exp10 = 0
	}
	return d, nil
}

func fastFloat32(d decimalFloat) (float32, bool) {
	if d.mant == 0 {
		if d.neg {
			return float32(math.Copysign(0, -1)), true
		}
		return 0, true
	}
	if d.truncated || d.mant > 1<<24 {
		return 0, false
	}
	var v float32
	switch {
	case d.exp10 == 0:
		v = float32(d.mant)
	case d.exp10 > 0 && d.exp10 < len(float32pow10):
		v = float32(d.mant) * float32pow10[d.exp10]
	case d.exp10 < 0 && -d.exp10 < len(float32pow10):
		v = float32(d.mant) / float32pow10[-d.exp10]
	default:
		return 0, false
	}
	if math.IsInf(float64(v), 0) {
		return 0, false
	}
	if d.neg {
		v = -v
	}
	return v, true
}

func fastFloat64(d decimalFloat) (float64, bool) {
	if d.mant == 0 {
		if d.neg {
			return math.Copysign(0, -1), true
		}
		return 0, true
	}
	if d.truncated || d.mant > 1<<53 {
		return 0, false
	}
	var v float64
	switch {
	case d.exp10 == 0:
		v = float64(d.mant)
	case d.exp10 > 0 && d.exp10 < len(float64pow10):
		v = float64(d.mant) * float64pow10[d.exp10]
	case d.exp10 < 0 && -d.exp10 < len(float64pow10):
		v = float64(d.mant) / float64pow10[-d.exp10]
	default:
		return 0, false
	}
	if math.IsInf(v, 0) {
		return 0, false
	}
	if d.neg {
		v = -v
	}
	return v, true
}

func unsafeBytesToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func (p *parser) skipValue() error {
	if p.hasStructuralLimits() {
		return p.skipValueLimited(1)
	}
	return p.skipValueNoLimit()
}

func (p *parser) skipValueNoLimit() error {
	p.skipWS()
	if p.i >= p.n {
		return Error{Code: ErrUnexpectedEOF, Offset: p.i}
	}
	switch p.buf[p.i] {
	case '{':
		return p.skipObject()
	case '[':
		return p.skipArray()
	case '"':
		return p.skipString()
	case 't':
		_, err := p.parseBoolOrNull(false)
		return err
	case 'f':
		_, err := p.parseBoolOrNull(false)
		return err
	case 'n':
		if p.tryNull() {
			return nil
		}
		return Error{Code: ErrInvalidNull, Offset: p.i}
	default:
		if p.buf[p.i] == '-' || (p.buf[p.i] >= '0' && p.buf[p.i] <= '9') {
			return p.skipNumber()
		}
		return Error{Code: ErrInvalidLiteral, Offset: p.i}
	}
}

func (p *parser) skipObject() error {
	if p.i >= p.n || p.buf[p.i] != '{' {
		return Error{Code: ErrExpectedObject, Offset: p.i}
	}
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == '}' {
		p.i++
		return nil
	}
	for {
		p.skipWS()
		if err := p.skipString(); err != nil {
			return err
		}
		p.skipWS()
		if p.i >= p.n {
			return Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		if p.buf[p.i] != ':' {
			return Error{Code: ErrExpectedColon, Offset: p.i}
		}
		p.i++
		p.skipWS()
		if err := p.skipValueNoLimit(); err != nil {
			return err
		}
		p.skipWS()
		if p.i >= p.n {
			return Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		switch p.buf[p.i] {
		case ',':
			p.i++
			continue
		case '}':
			p.i++
			return nil
		default:
			return Error{Code: ErrExpectedCommaOrEnd, Offset: p.i}
		}
	}
}

func (p *parser) skipArray() error {
	if p.i >= p.n || p.buf[p.i] != '[' {
		return Error{Code: ErrExpectedArray, Offset: p.i}
	}
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == ']' {
		p.i++
		return nil
	}
	for {
		p.skipWS()
		if err := p.skipValueNoLimit(); err != nil {
			return err
		}
		p.skipWS()
		if p.i >= p.n {
			return Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		switch p.buf[p.i] {
		case ',':
			p.i++
			continue
		case ']':
			p.i++
			return nil
		default:
			return Error{Code: ErrExpectedCommaOrEnd, Offset: p.i}
		}
	}
}

func (p *parser) skipValueLimited(depth int) error {
	p.skipWS()
	if p.opts.MaxDepth > 0 && depth > p.opts.MaxDepth {
		return Error{Code: ErrMaxDepth, Offset: p.i}
	}
	if p.i >= p.n {
		return Error{Code: ErrUnexpectedEOF, Offset: p.i}
	}
	switch p.buf[p.i] {
	case '{':
		return p.skipObjectLimited(depth)
	case '[':
		return p.skipArrayLimited(depth)
	case '"':
		return p.skipString()
	case 't':
		_, err := p.parseBoolOrNull(false)
		return err
	case 'f':
		_, err := p.parseBoolOrNull(false)
		return err
	case 'n':
		if p.tryNull() {
			return nil
		}
		return Error{Code: ErrInvalidNull, Offset: p.i}
	default:
		if p.buf[p.i] == '-' || (p.buf[p.i] >= '0' && p.buf[p.i] <= '9') {
			return p.skipNumber()
		}
		return Error{Code: ErrInvalidLiteral, Offset: p.i}
	}
}

func (p *parser) skipObjectLimited(depth int) error {
	if p.i >= p.n || p.buf[p.i] != '{' {
		return Error{Code: ErrExpectedObject, Offset: p.i}
	}
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == '}' {
		p.i++
		return nil
	}
	fields := 0
	for {
		if p.opts.MaxObjectFields > 0 && fields >= p.opts.MaxObjectFields {
			return Error{Code: ErrObjectTooLarge, Offset: p.i}
		}
		p.skipWS()
		if err := p.skipString(); err != nil {
			return err
		}
		p.skipWS()
		if p.i >= p.n {
			return Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		if p.buf[p.i] != ':' {
			return Error{Code: ErrExpectedColon, Offset: p.i}
		}
		p.i++
		p.skipWS()
		if err := p.skipValueLimited(depth + 1); err != nil {
			return err
		}
		fields++
		p.skipWS()
		if p.i >= p.n {
			return Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		switch p.buf[p.i] {
		case ',':
			p.i++
			p.skipWS()
			continue
		case '}':
			p.i++
			return nil
		default:
			return Error{Code: ErrExpectedCommaOrEnd, Offset: p.i}
		}
	}
}

func (p *parser) skipArrayLimited(depth int) error {
	if p.i >= p.n || p.buf[p.i] != '[' {
		return Error{Code: ErrExpectedArray, Offset: p.i}
	}
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == ']' {
		p.i++
		return nil
	}
	count := 0
	for {
		if p.opts.MaxArrayLength > 0 && count >= p.opts.MaxArrayLength {
			return Error{Code: ErrArrayTooLong, Offset: p.i}
		}
		p.skipWS()
		if err := p.skipValueLimited(depth + 1); err != nil {
			return err
		}
		count++
		p.skipWS()
		if p.i >= p.n {
			return Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		switch p.buf[p.i] {
		case ',':
			p.i++
			p.skipWS()
			continue
		case ']':
			p.i++
			return nil
		default:
			return Error{Code: ErrExpectedCommaOrEnd, Offset: p.i}
		}
	}
}

func (p *parser) skipNumber() error {
	start := p.i
	if p.i >= p.n {
		return Error{Code: ErrUnexpectedEOF, Offset: p.i}
	}
	if p.buf[p.i] == '-' {
		p.i++
		if p.i >= p.n {
			return Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
	}
	if p.buf[p.i] < '0' || p.buf[p.i] > '9' {
		return Error{Code: ErrInvalidNumber, Offset: p.i}
	}
	if p.buf[p.i] == '0' {
		p.i++
		if p.i < p.n && p.buf[p.i] >= '0' && p.buf[p.i] <= '9' {
			return Error{Code: ErrInvalidNumber, Offset: p.i}
		}
	} else {
		for p.i < p.n && p.buf[p.i] >= '0' && p.buf[p.i] <= '9' {
			p.i++
		}
	}
	if p.i < p.n && p.buf[p.i] == '.' {
		p.i++
		if p.i >= p.n || p.buf[p.i] < '0' || p.buf[p.i] > '9' {
			return Error{Code: ErrInvalidNumber, Offset: p.i}
		}
		for p.i < p.n && p.buf[p.i] >= '0' && p.buf[p.i] <= '9' {
			p.i++
		}
	}
	if p.i < p.n && (p.buf[p.i] == 'e' || p.buf[p.i] == 'E') {
		p.i++
		if p.i < p.n && (p.buf[p.i] == '+' || p.buf[p.i] == '-') {
			p.i++
		}
		if p.i >= p.n || p.buf[p.i] < '0' || p.buf[p.i] > '9' {
			return Error{Code: ErrInvalidNumber, Offset: p.i}
		}
		for p.i < p.n && p.buf[p.i] >= '0' && p.buf[p.i] <= '9' {
			p.i++
		}
	}
	if p.i == start || !isValueEnd(p) {
		return Error{Code: ErrInvalidNumber, Offset: p.i}
	}
	return nil
}

func (p *parser) decodeSlice(ti *typeInfo, ptr unsafe.Pointer) error {
	p.skipWS()
	if p.tryNull() {
		sh := (*reflect.SliceHeader)(ptr)
		sh.Data = 0
		sh.Len = 0
		sh.Cap = 0
		return nil
	}
	if p.i >= p.n || p.buf[p.i] != '[' {
		return Error{Code: ErrExpectedArray, Offset: p.i}
	}

	// For repeated decodes into an existing destination, primitive slices can be
	// decoded in one pass into the current backing array. Fresh or zero-capacity
	// slices keep the count-first path so they still get exact allocation.
	if isPrimitiveSliceFastKind(ti.elem.kind) {
		sh := (*reflect.SliceHeader)(ptr)
		if sh.Cap > 0 {
			if handled, err := p.decodePrimitiveSliceAppend(ti, ptr); handled {
				return err
			}
		}
	}

	count, err := p.countArrayElements()
	if err != nil {
		return err
	}
	if handled, err := p.decodePrimitiveSliceKnownCount(ti, ptr, count); handled {
		return err
	}
	return p.decodeSliceKnownCount(ti, ptr, count)
}

func isPrimitiveSliceFastKind(k kind) bool {
	switch k {
	case kindBool,
		kindInt, kindInt8, kindInt16, kindInt32, kindInt64,
		kindUint, kindUint8, kindUint16, kindUint32, kindUint64,
		kindFloat32, kindFloat64,
		kindString:
		return true
	default:
		return false
	}
}

func (p *parser) countArrayElements() (int, error) {
	save := p.i
	if p.buf[p.i] != '[' {
		return 0, Error{Code: ErrExpectedArray, Offset: p.i}
	}
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == ']' {
		p.i = save
		return 0, nil
	}
	count := 0
	for {
		if err := p.skipValue(); err != nil {
			p.i = save
			return 0, err
		}
		count++
		p.skipWS()
		if p.i >= p.n {
			p.i = save
			return 0, Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		switch p.buf[p.i] {
		case ',':
			p.i++
			p.skipWS()
			continue
		case ']':
			p.i = save
			return count, nil
		default:
			off := p.i
			p.i = save
			return 0, Error{Code: ErrExpectedCommaOrEnd, Offset: off}
		}
	}
}

func (p *parser) beginKnownCountArray(count int) (bool, error) {
	if p.buf[p.i] != '[' {
		return false, Error{Code: ErrExpectedArray, Offset: p.i}
	}
	p.i++
	p.skipWS()
	if count == 0 {
		if p.i >= p.n || p.buf[p.i] != ']' {
			return false, Error{Code: ErrExpectedCommaOrEnd, Offset: p.i}
		}
		p.i++
		return true, nil
	}
	return false, nil
}

func (p *parser) consumeArrayElementEnd(idx, count int) (bool, error) {
	p.skipWS()
	if idx == count-1 {
		if p.i >= p.n || p.buf[p.i] != ']' {
			return false, Error{Code: ErrExpectedCommaOrEnd, Offset: p.i}
		}
		p.i++
		return true, nil
	}
	if p.i >= p.n || p.buf[p.i] != ',' {
		return false, Error{Code: ErrExpectedCommaOrEnd, Offset: p.i}
	}
	p.i++
	p.skipWS()
	return false, nil
}

func (p *parser) consumeArrayAppendEnd() (bool, error) {
	p.skipWS()
	if p.i >= p.n {
		return false, Error{Code: ErrUnexpectedEOF, Offset: p.i}
	}
	switch p.buf[p.i] {
	case ',':
		p.i++
		p.skipWS()
		return false, nil
	case ']':
		p.i++
		return true, nil
	default:
		return false, Error{Code: ErrExpectedCommaOrEnd, Offset: p.i}
	}
}

func (p *parser) decodePrimitiveSliceAppend(ti *typeInfo, ptr unsafe.Pointer) (bool, error) {
	switch ti.elem.kind {
	case kindBool:
		return true, p.decodeBoolSliceAppend(ptr)
	case kindInt:
		return true, p.decodeIntSliceAppend(ptr)
	case kindInt8:
		return true, p.decodeInt8SliceAppend(ptr)
	case kindInt16:
		return true, p.decodeInt16SliceAppend(ptr)
	case kindInt32:
		return true, p.decodeInt32SliceAppend(ptr)
	case kindInt64:
		return true, p.decodeInt64SliceAppend(ptr)
	case kindUint:
		return true, p.decodeUintSliceAppend(ptr)
	case kindUint8:
		return true, p.decodeUint8SliceAppend(ptr)
	case kindUint16:
		return true, p.decodeUint16SliceAppend(ptr)
	case kindUint32:
		return true, p.decodeUint32SliceAppend(ptr)
	case kindUint64:
		return true, p.decodeUint64SliceAppend(ptr)
	case kindFloat32:
		return true, p.decodeFloat32SliceAppend(ptr)
	case kindFloat64:
		return true, p.decodeFloat64SliceAppend(ptr)
	case kindString:
		return true, p.decodeStringSliceAppend(ptr)
	default:
		return false, nil
	}
}

func (p *parser) decodePrimitiveSliceKnownCount(ti *typeInfo, ptr unsafe.Pointer, count int) (bool, error) {
	switch ti.elem.kind {
	case kindBool:
		return true, p.decodeBoolSliceKnownCount(ti, ptr, count)
	case kindInt:
		return true, p.decodeIntSliceKnownCount(ti, ptr, count)
	case kindInt8:
		return true, p.decodeInt8SliceKnownCount(ti, ptr, count)
	case kindInt16:
		return true, p.decodeInt16SliceKnownCount(ti, ptr, count)
	case kindInt32:
		return true, p.decodeInt32SliceKnownCount(ti, ptr, count)
	case kindInt64:
		return true, p.decodeInt64SliceKnownCount(ti, ptr, count)
	case kindUint:
		return true, p.decodeUintSliceKnownCount(ti, ptr, count)
	case kindUint8:
		return true, p.decodeUint8SliceKnownCount(ti, ptr, count)
	case kindUint16:
		return true, p.decodeUint16SliceKnownCount(ti, ptr, count)
	case kindUint32:
		return true, p.decodeUint32SliceKnownCount(ti, ptr, count)
	case kindUint64:
		return true, p.decodeUint64SliceKnownCount(ti, ptr, count)
	case kindFloat32:
		return true, p.decodeFloat32SliceKnownCount(ti, ptr, count)
	case kindFloat64:
		return true, p.decodeFloat64SliceKnownCount(ti, ptr, count)
	case kindString:
		return true, p.decodeStringSliceKnownCount(ti, ptr, count)
	default:
		return false, nil
	}
}

func (p *parser) decodeBoolSliceAppend(ptr unsafe.Pointer) error {
	out := *(*[]bool)(ptr)
	out = out[:0]
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == ']' {
		p.i++
		*(*[]bool)(ptr) = out
		return nil
	}
	for {
		v, err := p.parseBoolOrNull(false)
		if err != nil {
			return err
		}
		out = append(out, v)
		done, err := p.consumeArrayAppendEnd()
		if err != nil {
			return err
		}
		if done {
			*(*[]bool)(ptr) = out
			return nil
		}
	}
}

func (p *parser) decodeBoolSliceKnownCount(ti *typeInfo, ptr unsafe.Pointer, count int) error {
	base := prepareSlice(ti, ptr, count)
	if done, err := p.beginKnownCountArray(count); done || err != nil {
		return err
	}
	elemSize := ti.typ.Elem().Size()
	for idx := 0; idx < count; idx++ {
		v, err := p.parseBoolOrNull(false)
		if err != nil {
			return err
		}
		*(*bool)(unsafe.Add(base, uintptr(idx)*elemSize)) = v
		done, err := p.consumeArrayElementEnd(idx, count)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return nil
}

func (p *parser) decodeIntSliceAppend(ptr unsafe.Pointer) error {
	out := *(*[]int)(ptr)
	out = out[:0]
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == ']' {
		p.i++
		*(*[]int)(ptr) = out
		return nil
	}
	for {
		v, err := p.parseInt64Bits(intBits())
		if err != nil {
			return err
		}
		out = append(out, int(v))
		done, err := p.consumeArrayAppendEnd()
		if err != nil {
			return err
		}
		if done {
			*(*[]int)(ptr) = out
			return nil
		}
	}
}

func (p *parser) decodeIntSliceKnownCount(ti *typeInfo, ptr unsafe.Pointer, count int) error {
	base := prepareSlice(ti, ptr, count)
	if done, err := p.beginKnownCountArray(count); done || err != nil {
		return err
	}
	elemSize := ti.typ.Elem().Size()
	for idx := 0; idx < count; idx++ {
		v, err := p.parseInt64Bits(intBits())
		if err != nil {
			return err
		}
		*(*int)(unsafe.Add(base, uintptr(idx)*elemSize)) = int(v)
		done, err := p.consumeArrayElementEnd(idx, count)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return nil
}

func (p *parser) decodeInt8SliceAppend(ptr unsafe.Pointer) error {
	out := *(*[]int8)(ptr)
	out = out[:0]
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == ']' {
		p.i++
		*(*[]int8)(ptr) = out
		return nil
	}
	for {
		v, err := p.parseInt64Bits(8)
		if err != nil {
			return err
		}
		out = append(out, int8(v))
		done, err := p.consumeArrayAppendEnd()
		if err != nil {
			return err
		}
		if done {
			*(*[]int8)(ptr) = out
			return nil
		}
	}
}

func (p *parser) decodeInt8SliceKnownCount(ti *typeInfo, ptr unsafe.Pointer, count int) error {
	base := prepareSlice(ti, ptr, count)
	if done, err := p.beginKnownCountArray(count); done || err != nil {
		return err
	}
	elemSize := ti.typ.Elem().Size()
	for idx := 0; idx < count; idx++ {
		v, err := p.parseInt64Bits(8)
		if err != nil {
			return err
		}
		*(*int8)(unsafe.Add(base, uintptr(idx)*elemSize)) = int8(v)
		done, err := p.consumeArrayElementEnd(idx, count)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return nil
}

func (p *parser) decodeInt16SliceAppend(ptr unsafe.Pointer) error {
	out := *(*[]int16)(ptr)
	out = out[:0]
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == ']' {
		p.i++
		*(*[]int16)(ptr) = out
		return nil
	}
	for {
		v, err := p.parseInt64Bits(16)
		if err != nil {
			return err
		}
		out = append(out, int16(v))
		done, err := p.consumeArrayAppendEnd()
		if err != nil {
			return err
		}
		if done {
			*(*[]int16)(ptr) = out
			return nil
		}
	}
}

func (p *parser) decodeInt16SliceKnownCount(ti *typeInfo, ptr unsafe.Pointer, count int) error {
	base := prepareSlice(ti, ptr, count)
	if done, err := p.beginKnownCountArray(count); done || err != nil {
		return err
	}
	elemSize := ti.typ.Elem().Size()
	for idx := 0; idx < count; idx++ {
		v, err := p.parseInt64Bits(16)
		if err != nil {
			return err
		}
		*(*int16)(unsafe.Add(base, uintptr(idx)*elemSize)) = int16(v)
		done, err := p.consumeArrayElementEnd(idx, count)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return nil
}

func (p *parser) decodeInt32SliceAppend(ptr unsafe.Pointer) error {
	out := *(*[]int32)(ptr)
	out = out[:0]
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == ']' {
		p.i++
		*(*[]int32)(ptr) = out
		return nil
	}
	for {
		v, err := p.parseInt64Bits(32)
		if err != nil {
			return err
		}
		out = append(out, int32(v))
		done, err := p.consumeArrayAppendEnd()
		if err != nil {
			return err
		}
		if done {
			*(*[]int32)(ptr) = out
			return nil
		}
	}
}

func (p *parser) decodeInt32SliceKnownCount(ti *typeInfo, ptr unsafe.Pointer, count int) error {
	base := prepareSlice(ti, ptr, count)
	if done, err := p.beginKnownCountArray(count); done || err != nil {
		return err
	}
	elemSize := ti.typ.Elem().Size()
	for idx := 0; idx < count; idx++ {
		v, err := p.parseInt64Bits(32)
		if err != nil {
			return err
		}
		*(*int32)(unsafe.Add(base, uintptr(idx)*elemSize)) = int32(v)
		done, err := p.consumeArrayElementEnd(idx, count)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return nil
}

func (p *parser) decodeInt64SliceAppend(ptr unsafe.Pointer) error {
	out := *(*[]int64)(ptr)
	out = out[:0]
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == ']' {
		p.i++
		*(*[]int64)(ptr) = out
		return nil
	}
	for {
		v, err := p.parseInt64Bits(64)
		if err != nil {
			return err
		}
		out = append(out, v)
		done, err := p.consumeArrayAppendEnd()
		if err != nil {
			return err
		}
		if done {
			*(*[]int64)(ptr) = out
			return nil
		}
	}
}

func (p *parser) decodeInt64SliceKnownCount(ti *typeInfo, ptr unsafe.Pointer, count int) error {
	base := prepareSlice(ti, ptr, count)
	if done, err := p.beginKnownCountArray(count); done || err != nil {
		return err
	}
	elemSize := ti.typ.Elem().Size()
	for idx := 0; idx < count; idx++ {
		v, err := p.parseInt64Bits(64)
		if err != nil {
			return err
		}
		*(*int64)(unsafe.Add(base, uintptr(idx)*elemSize)) = v
		done, err := p.consumeArrayElementEnd(idx, count)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return nil
}

func (p *parser) decodeUintSliceAppend(ptr unsafe.Pointer) error {
	out := *(*[]uint)(ptr)
	out = out[:0]
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == ']' {
		p.i++
		*(*[]uint)(ptr) = out
		return nil
	}
	for {
		v, err := p.parseUint64Bits(uintBits())
		if err != nil {
			return err
		}
		out = append(out, uint(v))
		done, err := p.consumeArrayAppendEnd()
		if err != nil {
			return err
		}
		if done {
			*(*[]uint)(ptr) = out
			return nil
		}
	}
}

func (p *parser) decodeUintSliceKnownCount(ti *typeInfo, ptr unsafe.Pointer, count int) error {
	base := prepareSlice(ti, ptr, count)
	if done, err := p.beginKnownCountArray(count); done || err != nil {
		return err
	}
	elemSize := ti.typ.Elem().Size()
	for idx := 0; idx < count; idx++ {
		v, err := p.parseUint64Bits(uintBits())
		if err != nil {
			return err
		}
		*(*uint)(unsafe.Add(base, uintptr(idx)*elemSize)) = uint(v)
		done, err := p.consumeArrayElementEnd(idx, count)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return nil
}

func (p *parser) decodeUint8SliceAppend(ptr unsafe.Pointer) error {
	out := *(*[]uint8)(ptr)
	out = out[:0]
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == ']' {
		p.i++
		*(*[]uint8)(ptr) = out
		return nil
	}
	for {
		v, err := p.parseUint64Bits(8)
		if err != nil {
			return err
		}
		out = append(out, uint8(v))
		done, err := p.consumeArrayAppendEnd()
		if err != nil {
			return err
		}
		if done {
			*(*[]uint8)(ptr) = out
			return nil
		}
	}
}

func (p *parser) decodeUint8SliceKnownCount(ti *typeInfo, ptr unsafe.Pointer, count int) error {
	base := prepareSlice(ti, ptr, count)
	if done, err := p.beginKnownCountArray(count); done || err != nil {
		return err
	}
	elemSize := ti.typ.Elem().Size()
	for idx := 0; idx < count; idx++ {
		v, err := p.parseUint64Bits(8)
		if err != nil {
			return err
		}
		*(*uint8)(unsafe.Add(base, uintptr(idx)*elemSize)) = uint8(v)
		done, err := p.consumeArrayElementEnd(idx, count)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return nil
}

func (p *parser) decodeUint16SliceAppend(ptr unsafe.Pointer) error {
	out := *(*[]uint16)(ptr)
	out = out[:0]
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == ']' {
		p.i++
		*(*[]uint16)(ptr) = out
		return nil
	}
	for {
		v, err := p.parseUint64Bits(16)
		if err != nil {
			return err
		}
		out = append(out, uint16(v))
		done, err := p.consumeArrayAppendEnd()
		if err != nil {
			return err
		}
		if done {
			*(*[]uint16)(ptr) = out
			return nil
		}
	}
}

func (p *parser) decodeUint16SliceKnownCount(ti *typeInfo, ptr unsafe.Pointer, count int) error {
	base := prepareSlice(ti, ptr, count)
	if done, err := p.beginKnownCountArray(count); done || err != nil {
		return err
	}
	elemSize := ti.typ.Elem().Size()
	for idx := 0; idx < count; idx++ {
		v, err := p.parseUint64Bits(16)
		if err != nil {
			return err
		}
		*(*uint16)(unsafe.Add(base, uintptr(idx)*elemSize)) = uint16(v)
		done, err := p.consumeArrayElementEnd(idx, count)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return nil
}

func (p *parser) decodeUint32SliceAppend(ptr unsafe.Pointer) error {
	out := *(*[]uint32)(ptr)
	out = out[:0]
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == ']' {
		p.i++
		*(*[]uint32)(ptr) = out
		return nil
	}
	for {
		v, err := p.parseUint64Bits(32)
		if err != nil {
			return err
		}
		out = append(out, uint32(v))
		done, err := p.consumeArrayAppendEnd()
		if err != nil {
			return err
		}
		if done {
			*(*[]uint32)(ptr) = out
			return nil
		}
	}
}

func (p *parser) decodeUint32SliceKnownCount(ti *typeInfo, ptr unsafe.Pointer, count int) error {
	base := prepareSlice(ti, ptr, count)
	if done, err := p.beginKnownCountArray(count); done || err != nil {
		return err
	}
	elemSize := ti.typ.Elem().Size()
	for idx := 0; idx < count; idx++ {
		v, err := p.parseUint64Bits(32)
		if err != nil {
			return err
		}
		*(*uint32)(unsafe.Add(base, uintptr(idx)*elemSize)) = uint32(v)
		done, err := p.consumeArrayElementEnd(idx, count)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return nil
}

func (p *parser) decodeUint64SliceAppend(ptr unsafe.Pointer) error {
	out := *(*[]uint64)(ptr)
	out = out[:0]
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == ']' {
		p.i++
		*(*[]uint64)(ptr) = out
		return nil
	}
	for {
		v, err := p.parseUint64Bits(64)
		if err != nil {
			return err
		}
		out = append(out, v)
		done, err := p.consumeArrayAppendEnd()
		if err != nil {
			return err
		}
		if done {
			*(*[]uint64)(ptr) = out
			return nil
		}
	}
}

func (p *parser) decodeUint64SliceKnownCount(ti *typeInfo, ptr unsafe.Pointer, count int) error {
	base := prepareSlice(ti, ptr, count)
	if done, err := p.beginKnownCountArray(count); done || err != nil {
		return err
	}
	elemSize := ti.typ.Elem().Size()
	for idx := 0; idx < count; idx++ {
		v, err := p.parseUint64Bits(64)
		if err != nil {
			return err
		}
		*(*uint64)(unsafe.Add(base, uintptr(idx)*elemSize)) = v
		done, err := p.consumeArrayElementEnd(idx, count)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return nil
}

func (p *parser) decodeFloat32SliceAppend(ptr unsafe.Pointer) error {
	out := *(*[]float32)(ptr)
	out = out[:0]
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == ']' {
		p.i++
		*(*[]float32)(ptr) = out
		return nil
	}
	for {
		v, err := p.parseFloat32()
		if err != nil {
			return err
		}
		out = append(out, v)
		done, err := p.consumeArrayAppendEnd()
		if err != nil {
			return err
		}
		if done {
			*(*[]float32)(ptr) = out
			return nil
		}
	}
}

func (p *parser) decodeFloat32SliceKnownCount(ti *typeInfo, ptr unsafe.Pointer, count int) error {
	base := prepareSlice(ti, ptr, count)
	if done, err := p.beginKnownCountArray(count); done || err != nil {
		return err
	}
	elemSize := ti.typ.Elem().Size()
	for idx := 0; idx < count; idx++ {
		v, err := p.parseFloat32()
		if err != nil {
			return err
		}
		*(*float32)(unsafe.Add(base, uintptr(idx)*elemSize)) = v
		done, err := p.consumeArrayElementEnd(idx, count)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return nil
}

func (p *parser) decodeFloat64SliceAppend(ptr unsafe.Pointer) error {
	out := *(*[]float64)(ptr)
	out = out[:0]
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == ']' {
		p.i++
		*(*[]float64)(ptr) = out
		return nil
	}
	for {
		v, err := p.parseFloat64()
		if err != nil {
			return err
		}
		out = append(out, v)
		done, err := p.consumeArrayAppendEnd()
		if err != nil {
			return err
		}
		if done {
			*(*[]float64)(ptr) = out
			return nil
		}
	}
}

func (p *parser) decodeFloat64SliceKnownCount(ti *typeInfo, ptr unsafe.Pointer, count int) error {
	base := prepareSlice(ti, ptr, count)
	if done, err := p.beginKnownCountArray(count); done || err != nil {
		return err
	}
	elemSize := ti.typ.Elem().Size()
	for idx := 0; idx < count; idx++ {
		v, err := p.parseFloat64()
		if err != nil {
			return err
		}
		*(*float64)(unsafe.Add(base, uintptr(idx)*elemSize)) = v
		done, err := p.consumeArrayElementEnd(idx, count)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return nil
}

func (p *parser) decodeStringSliceAppend(ptr unsafe.Pointer) error {
	out := *(*[]string)(ptr)
	out = out[:0]
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == ']' {
		p.i++
		*(*[]string)(ptr) = out
		return nil
	}
	for {
		b, err := p.parseStringFully()
		if err != nil {
			return err
		}
		out = append(out, p.ownString(b))
		done, err := p.consumeArrayAppendEnd()
		if err != nil {
			return err
		}
		if done {
			*(*[]string)(ptr) = out
			return nil
		}
	}
}

func (p *parser) decodeStringSliceKnownCount(ti *typeInfo, ptr unsafe.Pointer, count int) error {
	base := prepareSlice(ti, ptr, count)
	if done, err := p.beginKnownCountArray(count); done || err != nil {
		return err
	}
	elemSize := ti.typ.Elem().Size()
	for idx := 0; idx < count; idx++ {
		b, err := p.parseStringFully()
		if err != nil {
			return err
		}
		setString(ti.typ.Elem(), unsafe.Add(base, uintptr(idx)*elemSize), p.ownString(b))
		done, err := p.consumeArrayElementEnd(idx, count)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return nil
}

func (p *parser) decodeSliceKnownCount(ti *typeInfo, ptr unsafe.Pointer, count int) error {
	elemSize := ti.typ.Elem().Size()
	base := prepareSlice(ti, ptr, count)

	if p.buf[p.i] != '[' {
		return Error{Code: ErrExpectedArray, Offset: p.i}
	}
	p.i++
	p.skipWS()
	if count == 0 {
		if p.i >= p.n || p.buf[p.i] != ']' {
			return Error{Code: ErrExpectedCommaOrEnd, Offset: p.i}
		}
		p.i++
		return nil
	}
	for idx := 0; idx < count; idx++ {
		elemPtr := unsafe.Add(base, uintptr(idx)*elemSize)
		if err := p.decodeInto(ti.elem, elemPtr); err != nil {
			return withPath(err, pathIndex(idx))
		}
		p.skipWS()
		if idx == count-1 {
			if p.i >= p.n || p.buf[p.i] != ']' {
				return Error{Code: ErrExpectedCommaOrEnd, Offset: p.i}
			}
			p.i++
			return nil
		}
		if p.i >= p.n || p.buf[p.i] != ',' {
			return Error{Code: ErrExpectedCommaOrEnd, Offset: p.i}
		}
		p.i++
		p.skipWS()
	}
	return nil
}

func prepareSlice(ti *typeInfo, ptr unsafe.Pointer, count int) unsafe.Pointer {
	sh := (*reflect.SliceHeader)(ptr)
	if sh.Cap >= count {
		sh.Len = count
		if count == 0 || sh.Data == 0 {
			return nil
		}
		return unsafe.Pointer(sh.Data)
	}

	// Built-in primitive slice allocations avoid reflection. Arbitrary composite
	// slices and named slice types whose layout cannot be constructed with a
	// typed make fall back to reflect.MakeSlice.
	switch ti.elem.kind {
	case kindBool:
		v := make([]bool, count)
		*(*[]bool)(ptr) = v
		if count == 0 {
			return nil
		}
		return unsafe.Pointer(&v[0])
	case kindInt:
		v := make([]int, count)
		*(*[]int)(ptr) = v
		if count == 0 {
			return nil
		}
		return unsafe.Pointer(&v[0])
	case kindInt8:
		v := make([]int8, count)
		*(*[]int8)(ptr) = v
		if count == 0 {
			return nil
		}
		return unsafe.Pointer(&v[0])
	case kindInt16:
		v := make([]int16, count)
		*(*[]int16)(ptr) = v
		if count == 0 {
			return nil
		}
		return unsafe.Pointer(&v[0])
	case kindInt32:
		v := make([]int32, count)
		*(*[]int32)(ptr) = v
		if count == 0 {
			return nil
		}
		return unsafe.Pointer(&v[0])
	case kindInt64:
		v := make([]int64, count)
		*(*[]int64)(ptr) = v
		if count == 0 {
			return nil
		}
		return unsafe.Pointer(&v[0])
	case kindUint:
		v := make([]uint, count)
		*(*[]uint)(ptr) = v
		if count == 0 {
			return nil
		}
		return unsafe.Pointer(&v[0])
	case kindUint8:
		v := make([]uint8, count)
		*(*[]uint8)(ptr) = v
		if count == 0 {
			return nil
		}
		return unsafe.Pointer(&v[0])
	case kindUint16:
		v := make([]uint16, count)
		*(*[]uint16)(ptr) = v
		if count == 0 {
			return nil
		}
		return unsafe.Pointer(&v[0])
	case kindUint32:
		v := make([]uint32, count)
		*(*[]uint32)(ptr) = v
		if count == 0 {
			return nil
		}
		return unsafe.Pointer(&v[0])
	case kindUint64:
		v := make([]uint64, count)
		*(*[]uint64)(ptr) = v
		if count == 0 {
			return nil
		}
		return unsafe.Pointer(&v[0])
	case kindFloat32:
		v := make([]float32, count)
		*(*[]float32)(ptr) = v
		if count == 0 {
			return nil
		}
		return unsafe.Pointer(&v[0])
	case kindFloat64:
		v := make([]float64, count)
		*(*[]float64)(ptr) = v
		if count == 0 {
			return nil
		}
		return unsafe.Pointer(&v[0])
	case kindString:
		v := make([]string, count)
		*(*[]string)(ptr) = v
		if count == 0 {
			return nil
		}
		return unsafe.Pointer(&v[0])
	case kindBytes:
		v := make([][]byte, count)
		*(*[][]byte)(ptr) = v
		if count == 0 {
			return nil
		}
		return unsafe.Pointer(&v[0])
	}

	rv := reflect.MakeSlice(ti.typ, count, count)
	reflect.NewAt(ti.typ, ptr).Elem().Set(rv)
	if count == 0 {
		return nil
	}
	return unsafe.Pointer(rv.Pointer())
}

func (p *parser) decodeArray(ti *typeInfo, ptr unsafe.Pointer) error {
	p.skipWS()
	if p.i >= p.n || p.buf[p.i] != '[' {
		return Error{Code: ErrExpectedArray, Offset: p.i}
	}
	elemSize := ti.typ.Elem().Size()
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == ']' {
		p.i++
		zeroArrayTail(ti, ptr, 0)
		return nil
	}

	idx := 0
	for {
		if idx >= ti.len {
			return Error{Code: ErrArrayTooLong, Offset: p.i}
		}
		elemPtr := unsafe.Add(ptr, uintptr(idx)*elemSize)
		if err := p.decodeInto(ti.elem, elemPtr); err != nil {
			return withPath(err, pathIndex(idx))
		}
		idx++
		p.skipWS()
		if p.i >= p.n {
			return Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		switch p.buf[p.i] {
		case ',':
			p.i++
			p.skipWS()
			continue
		case ']':
			p.i++
			zeroArrayTail(ti, ptr, idx)
			return nil
		default:
			return Error{Code: ErrExpectedCommaOrEnd, Offset: p.i}
		}
	}
}

func zeroArrayTail(ti *typeInfo, ptr unsafe.Pointer, from int) {
	if from >= ti.len {
		return
	}
	elemSize := ti.typ.Elem().Size()
	for idx := from; idx < ti.len; idx++ {
		elemPtr := unsafe.Add(ptr, uintptr(idx)*elemSize)
		switch ti.elem.kind {
		case kindBool:
			*(*bool)(elemPtr) = false
		case kindInt:
			*(*int)(elemPtr) = 0
		case kindInt8:
			*(*int8)(elemPtr) = 0
		case kindInt16:
			*(*int16)(elemPtr) = 0
		case kindInt32:
			*(*int32)(elemPtr) = 0
		case kindInt64:
			*(*int64)(elemPtr) = 0
		case kindUint:
			*(*uint)(elemPtr) = 0
		case kindUint8:
			*(*uint8)(elemPtr) = 0
		case kindUint16:
			*(*uint16)(elemPtr) = 0
		case kindUint32:
			*(*uint32)(elemPtr) = 0
		case kindUint64:
			*(*uint64)(elemPtr) = 0
		case kindFloat32:
			*(*float32)(elemPtr) = 0
		case kindFloat64:
			*(*float64)(elemPtr) = 0
		case kindString:
			*(*string)(elemPtr) = ""
		case kindBytes, kindSlice:
			sh := (*reflect.SliceHeader)(elemPtr)
			sh.Data = 0
			sh.Len = 0
			sh.Cap = 0
		case kindPtr, kindMap:
			*(*unsafe.Pointer)(elemPtr) = nil
		case kindAny:
			*(*interface{})(elemPtr) = nil
		case kindTime:
			*(*time.Time)(elemPtr) = time.Time{}
		case kindJSONNumber:
			*(*json.Number)(elemPtr) = ""
		default:
			reflect.NewAt(ti.typ.Elem(), elemPtr).Elem().SetZero()
		}
	}
}

func (p *parser) decodeMap(ti *typeInfo, ptr unsafe.Pointer) error {
	p.skipWS()
	if handled, err := p.decodeTypedStringMap(ti, ptr); handled {
		return err
	}

	mv := reflect.NewAt(ti.typ, ptr).Elem()
	if p.tryNull() {
		mv.SetZero()
		return nil
	}
	if p.i >= p.n || p.buf[p.i] != '{' {
		return Error{Code: ErrExpectedObject, Offset: p.i}
	}
	count, err := p.countObjectMembers()
	if err != nil {
		return err
	}
	if mv.IsNil() {
		mv.Set(reflect.MakeMapWithSize(ti.typ, count))
	}
	p.i++
	p.skipWS()
	if count == 0 {
		if p.i >= p.n || p.buf[p.i] != '}' {
			return Error{Code: ErrExpectedCommaOrEnd, Offset: p.i}
		}
		p.i++
		return nil
	}
	keyType := ti.typ.Key()
	valType := ti.typ.Elem()
	for idx := 0; idx < count; idx++ {
		keyBytes, err := p.parseKey()
		if err != nil {
			return err
		}
		p.skipWS()
		if p.i >= p.n {
			return Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		if p.buf[p.i] != ':' {
			return Error{Code: ErrExpectedColon, Offset: p.i, Field: keyBytes, Path: pathField(keyBytes)}
		}
		p.i++
		p.skipWS()

		key := reflect.New(keyType).Elem()
		key.SetString(p.ownString(keyBytes))
		val := reflect.New(valType)
		if err := p.decodeInto(ti.elem, unsafe.Pointer(val.Pointer())); err != nil {
			return withPath(err, pathField(keyBytes))
		}
		mv.SetMapIndex(key, val.Elem())

		p.skipWS()
		if p.i >= p.n {
			return Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		if idx == count-1 {
			if p.buf[p.i] != '}' {
				return Error{Code: ErrExpectedCommaOrEnd, Offset: p.i}
			}
			p.i++
			return nil
		}
		if p.buf[p.i] != ',' {
			return Error{Code: ErrExpectedCommaOrEnd, Offset: p.i}
		}
		p.i++
		p.skipWS()
	}
	return nil
}

func (p *parser) decodeTypedStringMap(ti *typeInfo, ptr unsafe.Pointer) (bool, error) {
	switch ti.typ {
	case mapStringStringType:
		return true, p.decodeMapStringString(ptr)
	case mapStringIntType:
		return true, p.decodeMapStringInt(ptr)
	case mapStringInt64Type:
		return true, p.decodeMapStringInt64(ptr)
	case mapStringUint64Type:
		return true, p.decodeMapStringUint64(ptr)
	case mapStringFloat64Type:
		return true, p.decodeMapStringFloat64(ptr)
	case mapStringBoolType:
		return true, p.decodeMapStringBool(ptr)
	default:
		return false, nil
	}
}

func (p *parser) consumeObjectAppendEnd() (bool, error) {
	p.skipWS()
	if p.i >= p.n {
		return false, Error{Code: ErrUnexpectedEOF, Offset: p.i}
	}
	switch p.buf[p.i] {
	case ',':
		p.i++
		p.skipWS()
		return false, nil
	case '}':
		p.i++
		return true, nil
	default:
		return false, Error{Code: ErrExpectedCommaOrEnd, Offset: p.i}
	}
}

func (p *parser) decodeMapStringString(ptr unsafe.Pointer) error {
	mp := (*map[string]string)(ptr)
	if p.tryNull() {
		*mp = nil
		return nil
	}
	if p.i >= p.n || p.buf[p.i] != '{' {
		return Error{Code: ErrExpectedObject, Offset: p.i}
	}
	m := *mp
	if m == nil {
		count, err := p.countObjectMembers()
		if err != nil {
			return err
		}
		m = make(map[string]string, count)
	}
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == '}' {
		p.i++
		*mp = m
		return nil
	}
	for {
		key, err := p.parseKey()
		if err != nil {
			return err
		}
		p.skipWS()
		if p.i >= p.n {
			return Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		if p.buf[p.i] != ':' {
			return Error{Code: ErrExpectedColon, Offset: p.i, Field: key}
		}
		p.i++
		p.skipWS()
		v, err := p.parseStringFully()
		if err != nil {
			return err
		}
		m[p.ownString(key)] = p.ownString(v)
		done, err := p.consumeObjectAppendEnd()
		if err != nil {
			return err
		}
		if done {
			*mp = m
			return nil
		}
	}
}

func (p *parser) decodeMapStringInt(ptr unsafe.Pointer) error {
	mp := (*map[string]int)(ptr)
	if p.tryNull() {
		*mp = nil
		return nil
	}
	if p.i >= p.n || p.buf[p.i] != '{' {
		return Error{Code: ErrExpectedObject, Offset: p.i}
	}
	m := *mp
	if m == nil {
		count, err := p.countObjectMembers()
		if err != nil {
			return err
		}
		m = make(map[string]int, count)
	}
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == '}' {
		p.i++
		*mp = m
		return nil
	}
	for {
		key, err := p.parseKey()
		if err != nil {
			return err
		}
		p.skipWS()
		if p.i >= p.n {
			return Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		if p.buf[p.i] != ':' {
			return Error{Code: ErrExpectedColon, Offset: p.i, Field: key}
		}
		p.i++
		p.skipWS()
		v, err := p.parseInt64Bits(intBits())
		if err != nil {
			return err
		}
		m[p.ownString(key)] = int(v)
		done, err := p.consumeObjectAppendEnd()
		if err != nil {
			return err
		}
		if done {
			*mp = m
			return nil
		}
	}
}

func (p *parser) decodeMapStringInt64(ptr unsafe.Pointer) error {
	mp := (*map[string]int64)(ptr)
	if p.tryNull() {
		*mp = nil
		return nil
	}
	if p.i >= p.n || p.buf[p.i] != '{' {
		return Error{Code: ErrExpectedObject, Offset: p.i}
	}
	m := *mp
	if m == nil {
		count, err := p.countObjectMembers()
		if err != nil {
			return err
		}
		m = make(map[string]int64, count)
	}
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == '}' {
		p.i++
		*mp = m
		return nil
	}
	for {
		key, err := p.parseKey()
		if err != nil {
			return err
		}
		p.skipWS()
		if p.i >= p.n {
			return Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		if p.buf[p.i] != ':' {
			return Error{Code: ErrExpectedColon, Offset: p.i, Field: key}
		}
		p.i++
		p.skipWS()
		v, err := p.parseInt64Bits(64)
		if err != nil {
			return err
		}
		m[p.ownString(key)] = v
		done, err := p.consumeObjectAppendEnd()
		if err != nil {
			return err
		}
		if done {
			*mp = m
			return nil
		}
	}
}

func (p *parser) decodeMapStringUint64(ptr unsafe.Pointer) error {
	mp := (*map[string]uint64)(ptr)
	if p.tryNull() {
		*mp = nil
		return nil
	}
	if p.i >= p.n || p.buf[p.i] != '{' {
		return Error{Code: ErrExpectedObject, Offset: p.i}
	}
	m := *mp
	if m == nil {
		count, err := p.countObjectMembers()
		if err != nil {
			return err
		}
		m = make(map[string]uint64, count)
	}
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == '}' {
		p.i++
		*mp = m
		return nil
	}
	for {
		key, err := p.parseKey()
		if err != nil {
			return err
		}
		p.skipWS()
		if p.i >= p.n {
			return Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		if p.buf[p.i] != ':' {
			return Error{Code: ErrExpectedColon, Offset: p.i, Field: key}
		}
		p.i++
		p.skipWS()
		v, err := p.parseUint64Bits(64)
		if err != nil {
			return err
		}
		m[p.ownString(key)] = v
		done, err := p.consumeObjectAppendEnd()
		if err != nil {
			return err
		}
		if done {
			*mp = m
			return nil
		}
	}
}

func (p *parser) decodeMapStringFloat64(ptr unsafe.Pointer) error {
	mp := (*map[string]float64)(ptr)
	if p.tryNull() {
		*mp = nil
		return nil
	}
	if p.i >= p.n || p.buf[p.i] != '{' {
		return Error{Code: ErrExpectedObject, Offset: p.i}
	}
	m := *mp
	if m == nil {
		count, err := p.countObjectMembers()
		if err != nil {
			return err
		}
		m = make(map[string]float64, count)
	}
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == '}' {
		p.i++
		*mp = m
		return nil
	}
	for {
		key, err := p.parseKey()
		if err != nil {
			return err
		}
		p.skipWS()
		if p.i >= p.n {
			return Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		if p.buf[p.i] != ':' {
			return Error{Code: ErrExpectedColon, Offset: p.i, Field: key}
		}
		p.i++
		p.skipWS()
		v, err := p.parseFloat64()
		if err != nil {
			return err
		}
		m[p.ownString(key)] = v
		done, err := p.consumeObjectAppendEnd()
		if err != nil {
			return err
		}
		if done {
			*mp = m
			return nil
		}
	}
}

func (p *parser) decodeMapStringBool(ptr unsafe.Pointer) error {
	mp := (*map[string]bool)(ptr)
	if p.tryNull() {
		*mp = nil
		return nil
	}
	if p.i >= p.n || p.buf[p.i] != '{' {
		return Error{Code: ErrExpectedObject, Offset: p.i}
	}
	m := *mp
	if m == nil {
		count, err := p.countObjectMembers()
		if err != nil {
			return err
		}
		m = make(map[string]bool, count)
	}
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == '}' {
		p.i++
		*mp = m
		return nil
	}
	for {
		key, err := p.parseKey()
		if err != nil {
			return err
		}
		p.skipWS()
		if p.i >= p.n {
			return Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		if p.buf[p.i] != ':' {
			return Error{Code: ErrExpectedColon, Offset: p.i, Field: key}
		}
		p.i++
		p.skipWS()
		v, err := p.parseBoolOrNull(false)
		if err != nil {
			return err
		}
		m[p.ownString(key)] = v
		done, err := p.consumeObjectAppendEnd()
		if err != nil {
			return err
		}
		if done {
			*mp = m
			return nil
		}
	}
}

func (p *parser) countObjectMembers() (int, error) {
	save := p.i
	if p.buf[p.i] != '{' {
		return 0, Error{Code: ErrExpectedObject, Offset: p.i}
	}
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == '}' {
		p.i = save
		return 0, nil
	}
	count := 0
	for {
		if err := p.skipString(); err != nil {
			p.i = save
			return 0, err
		}
		p.skipWS()
		if p.i >= p.n {
			p.i = save
			return 0, Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		if p.buf[p.i] != ':' {
			off := p.i
			p.i = save
			return 0, Error{Code: ErrExpectedColon, Offset: off}
		}
		p.i++
		p.skipWS()
		if err := p.skipValue(); err != nil {
			p.i = save
			return 0, err
		}
		count++
		p.skipWS()
		if p.i >= p.n {
			p.i = save
			return 0, Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		switch p.buf[p.i] {
		case ',':
			p.i++
			p.skipWS()
			continue
		case '}':
			p.i = save
			return count, nil
		default:
			off := p.i
			p.i = save
			return 0, Error{Code: ErrExpectedCommaOrEnd, Offset: off}
		}
	}
}

func (p *parser) parseAny() (interface{}, error) {
	p.skipWS()
	if p.i >= p.n {
		return nil, Error{Code: ErrUnexpectedEOF, Offset: p.i}
	}
	switch p.buf[p.i] {
	case '{':
		return p.parseAnyObject()
	case '[':
		return p.parseAnyArray()
	case '"':
		b, err := p.parseStringFully()
		if err != nil {
			return nil, err
		}
		return p.ownString(b), nil
	case 't':
		v, err := p.parseBoolOrNull(false)
		return v, err
	case 'f':
		v, err := p.parseBoolOrNull(false)
		return v, err
	case 'n':
		if p.tryNull() {
			return nil, nil
		}
		return nil, Error{Code: ErrInvalidNull, Offset: p.i}
	default:
		if p.buf[p.i] == '-' || (p.buf[p.i] >= '0' && p.buf[p.i] <= '9') {
			return p.parseFloat64()
		}
		return nil, Error{Code: ErrInvalidLiteral, Offset: p.i}
	}
}

func (p *parser) parseAnyArray() ([]interface{}, error) {
	if p.i >= p.n || p.buf[p.i] != '[' {
		return nil, Error{Code: ErrExpectedArray, Offset: p.i}
	}
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == ']' {
		p.i++
		return []interface{}{}, nil
	}

	out := make([]interface{}, 0, 8)
	for {
		v, err := p.parseAny()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.skipWS()
		if p.i >= p.n {
			return nil, Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		switch p.buf[p.i] {
		case ',':
			p.i++
			p.skipWS()
		case ']':
			p.i++
			return out, nil
		default:
			return nil, Error{Code: ErrExpectedCommaOrEnd, Offset: p.i}
		}
	}
}

func (p *parser) parseAnyObject() (map[string]interface{}, error) {
	if p.i >= p.n || p.buf[p.i] != '{' {
		return nil, Error{Code: ErrExpectedObject, Offset: p.i}
	}
	p.i++
	p.skipWS()
	if p.i < p.n && p.buf[p.i] == '}' {
		p.i++
		return map[string]interface{}{}, nil
	}

	out := make(map[string]interface{}, 8)
	for {
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		p.skipWS()
		if p.i >= p.n {
			return nil, Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		if p.buf[p.i] != ':' {
			return nil, Error{Code: ErrExpectedColon, Offset: p.i, Field: key}
		}
		p.i++
		p.skipWS()
		keyString := p.ownString(key)
		v, err := p.parseAny()
		if err != nil {
			return nil, err
		}
		out[keyString] = v
		p.skipWS()
		if p.i >= p.n {
			return nil, Error{Code: ErrUnexpectedEOF, Offset: p.i}
		}
		switch p.buf[p.i] {
		case ',':
			p.i++
			p.skipWS()
		case '}':
			p.i++
			return out, nil
		default:
			return nil, Error{Code: ErrExpectedCommaOrEnd, Offset: p.i}
		}
	}
}
