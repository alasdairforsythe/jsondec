# jsondec

jsondec is a Go JSON decoding library built around a registration pattern: you compile a decoder for a struct type once and reuse it. Beyond performance, it adds field-level semantics that `encoding/json` does not have — required fields, presence detection, null vs absent distinction, forbidden fields, structural size limits, and union field types — without requiring custom `UnmarshalJSON` implementations.

---

## Why not encoding/json

`encoding/json` has five gaps that matter in production API servers:

**No required fields.** If a required field is missing from the JSON, `encoding/json` silently leaves it at its zero value. You cannot distinguish `{"count": 0}` from `{}`.

**No presence detection.** There is no way to know whether a field was sent at all. This makes PATCH endpoints impossible to implement correctly without wrapper types or sentinel values.

**No null vs absent distinction.** `{"ptr": null}` and `{}` both result in a nil pointer. Distinguishing them requires custom unmarshaling on every type that needs it.

**No structural limits.** You cannot reject a payload that is too large, too deeply nested, or has too many fields. This is a security concern when decoding untrusted input.

**No forbidden fields.** You cannot declare that a particular key must never appear, which matters for privileged fields.

**`[]byte` decodes from base64.** In `encoding/json`, a `[]byte` field expects a base64-encoded JSON string — `"aGVsbG8="` becomes `[]byte("hello")`. In jsondec, `[]byte` stores the raw string bytes — `"aGVsbG8="` becomes `[]byte("aGVsbG8=")`. This is a silent data corruption risk when migrating. If you need base64 decoding, use a `string` field and decode it explicitly.

jsondec solves all of the above with struct tags and typed field declarations, and adds union field types for APIs that return either a string or an array, or either a string or an embedded object.

---

## Install

```
go get github.com/your-org/jsondec
```

---

## Usage

Declare a decoder once at package level. Call it anywhere.

```go
type User struct {
    ID   int    `json:"id,required"`
    Name string `json:"name"`
    Tags []int  `json:"tags"`
}

var DecodeUser = jsondec.RegisterDecoder[User]()

var u User
err := DecodeUser(data, &u)
```

`RegisterDecoder[T]()` compiles type information for `T` at startup and returns a `DecodeFunc[T]` — a plain function, concurrent-safe, that you own and can name, test, and pass around. Every call to it after that pays no reflection cost.

If you need options applied to every decode call, use `RegisterDecoderOptions`:

```go
var DecodeUser = jsondec.RegisterDecoderOptions[User](jsondec.DecoderOptions{
    DisallowUnknownFields: true,
    MaxBytes:              1 << 16,
})
```

Both functions panic with `CompileError` at startup if `T` contains an unsupported type or a duplicate JSON field name. This is intentional — misconfiguration is caught before the program serves traffic.

---

## Performance

Benchmarks run on Linux/amd64, Intel Xeon @ 2.80GHz.

Each cell: ns/op · MB/s · allocs/op. Lower ns/op and allocs/op are better; higher MB/s is better.

| Benchmark | jsondec | goccy/go-json | encoding/json/v2 | encoding/json |
|---|---:|---:|---:|---:|
| UserProfile (858 B) | 3,793 ns · 242 MB/s · 3 allocs | 2,856 ns · 314 MB/s · 7 allocs | 6,539 ns · 137 MB/s · 13 allocs | 13,560 ns · 66 MB/s · 34 allocs |
| LogEntry (817 B) | 2,892 ns · 283 MB/s · 4 allocs | 3,333 ns · 245 MB/s · 15 allocs | 5,859 ns · 139 MB/s · 6 allocs | 13,135 ns · 62 MB/s · 40 allocs |
| Order (1,845 B) | 6,921 ns · 267 MB/s · 4 allocs | 6,238 ns · 298 MB/s · 5 allocs | 12,458 ns · 148 MB/s · 13 allocs | 28,459 ns · 65 MB/s · 47 allocs |
| GitHubEvent (2,584 B) | 9,913 ns · 261 MB/s · 8 allocs | 8,709 ns · 297 MB/s · 18 allocs | 19,029 ns · 136 MB/s · 49 allocs | 37,877 ns · 68 MB/s · 86 allocs |
| Config (454 B) | 2,131 ns · 213 MB/s · 3 allocs | 1,945 ns · 234 MB/s · 6 allocs | 3,703 ns · 123 MB/s · 11 allocs | 6,892 ns · 66 MB/s · 21 allocs |
| OpenAPI (8,836 B) | 76,042 ns · 116 MB/s · 256 allocs | 62,325 ns · 142 MB/s · 300 allocs | 111,857 ns · 79 MB/s · 308 allocs | 188,266 ns · 47 MB/s · 488 allocs |

jsondec is about 2.5x–4.5x faster than `encoding/json` and about 1.5x–2.0x faster than `encoding/json/v2` on these fixtures. Against `goccy/go-json`, jsondec is faster on the map-heavy LogEntry fixture and slower on most struct-heavy fixtures, while generally using fewer allocations.

---

## Struct tags

jsondec reads the `json` struct tag. The full syntax is:

```
`json:"<name>,<options>"`
```

Where `<name>` is the JSON key to read from (empty means use the Go field name), and the only option jsondec recognises is `required`. Everything else (`omitempty`, etc.) is ignored — jsondec is decode-only.

```go
type Order struct {
    // Required fields — decoding fails if these keys are absent.
    ID         int    `json:"id,required"`
    CustomerID int    `json:"customer_id,required"`

    // Optional fields — zero value if absent, no error.
    Status string `json:"status"`
    Notes  string `json:"notes"`

    // Renamed field — reads from "ts", not "CreatedAt".
    CreatedAt time.Time `json:"ts"`

    // Skipped field — never populated, even if the key is present.
    InternalCache string `json:"-"`

    // Forbidden field — decoding fails if this key appears.
    // See the Forbidden type in the Field Types section.
    AdminOverride jsondec.Forbidden `json:"__admin"`
}
```

A struct can have up to 64 required fields. Fields without a `json` tag use the Go field name as the key.

---

## Field types

These types are used as struct field types. They are how you express field-level semantics beyond "decode this value or leave it at zero."

### Presence and nullability

These four types cover every combination of "was this field in the JSON" and "was it null." The right one to use depends entirely on which of those questions your application needs to answer.

Consider a PATCH endpoint for a user profile. The client sends only what it wants to change. Three different fields have three different requirements:

```go
type UserPatch struct {
    // Name can be updated but not cleared — null is not meaningful here.
    // Absent: don't touch. Present with value: update. Present with null: error.
    Name jsondec.Optional[string] `json:"name"`

    // Bio can be updated or explicitly cleared by sending null.
    // The field is always present in responses, but may be null.
    // Absent: leave as-is (zero value, Null=false). Null: clear it. Value: update.
    Bio jsondec.Nullable[string] `json:"bio"`

    // Email supports full PATCH semantics: absent, null, and value are all distinct.
    // Absent: don't touch. Null: clear the email address. Value: update it.
    Email jsondec.OptionalNullable[string] `json:"email"`

    // AdminNote: we want to know if the caller sent this key at all,
    // but we store the value elsewhere and don't need it decoded here.
    AdminNote jsondec.Present `json:"admin_note"`
}
```

After decoding:

```go
// Name
if patch.Name.Present {
    db.SetName(patch.Name.Value)
}

// Bio
if patch.Bio.Null {
    db.ClearBio()
} else if patch.Bio.Value != "" {
    db.SetBio(patch.Bio.Value)
}

// Email
if patch.Email.Present {
    if patch.Email.Null {
        db.ClearEmail()
    } else {
        db.SetEmail(patch.Email.Value)
    }
}

// AdminNote
if patch.AdminNote.Present {
    audit.Log("caller included admin_note key, null=%v", patch.AdminNote.Null)
}
```

**`Optional[T any]`**

```go
type Optional[T any] struct {
    Present bool
    Value   T
}
```

`Present` is false when the field was absent; true when it appeared with a value. Explicit JSON null is accepted only if `T` itself accepts null — `Optional[*string]` accepts null (sets `Value` to nil pointer), `Optional[string]` does not.

**`Nullable[T any]`**

```go
type Nullable[T any] struct {
    Null  bool
    Value T
}
```

`Null` is true when the JSON value was `null`. Does not distinguish absent from null — a missing field leaves `Null=false` and `Value` at its zero value, identical to a present field with the zero value. Use `OptionalNullable` if you need that distinction.

**`OptionalNullable[T any]`**

```go
type OptionalNullable[T any] struct {
    Present bool
    Null    bool
    Value   T
}
```

Covers all three states: absent (`Present=false`), null (`Present=true, Null=true`), value (`Present=true, Null=false, Value=decoded`).

**`Present`**

```go
type Present struct {
    Present bool
    Null    bool
}
```

Records presence and whether the value was null, without storing the value itself. The JSON value is validated and skipped.

---

### Raw preservation

These types store a validated JSON value without decoding it into Go types. The bytes they store are a slice of the original input, preserving whitespace exactly as it appeared.

| Type | Accepted JSON | Rejects |
|---|---|---|
| `RawValue` | Any valid value | Nothing valid |
| `RawObject` | Object or null | Arrays, strings, numbers, booleans |
| `RawArray` | Array or null | Objects, strings, numbers, booleans |
| `RawUnion` | Any valid value | Nothing valid — also records the kind |

```go
type Config struct {
    // Schema can be any JSON object — store it raw for later validation.
    Schema jsondec.RawObject `json:"schema"`

    // Tags can be any JSON array — store raw to decode later with a specific decoder.
    Tags jsondec.RawArray `json:"tags"`

    // Value is a union field — could be a string, number, or object depending on type.
    Value jsondec.RawUnion `json:"value"`
}

// After decoding, branch on kind:
switch config.Value.Kind {
case jsondec.KindString:
    // decode config.Value.Bytes as a string
case jsondec.KindObject:
    // decode config.Value.Bytes as a specific struct
case jsondec.KindNumber:
    // decode config.Value.Bytes as a number
}
```

**`RawValue`**

```go
type RawValue struct {
    Bytes   []byte
    Present bool
}
```

**`RawObject`**

```go
type RawObject struct {
    Bytes   []byte
    Present bool
}
```

**`RawArray`**

```go
type RawArray struct {
    Bytes   []byte
    Present bool
}
```

**`RawUnion`**

```go
type RawUnion struct {
    Kind  JSONKind
    Bytes []byte
}
```

`Kind` is one of: `KindNull`, `KindObject`, `KindArray`, `KindString`, `KindNumber`, `KindBool`, `KindInvalid`.

---

### Union fields

jsondec has three ways to handle a JSON field that can be more than one type:

`RawUnion` — covered above under raw preservation — accepts any JSON type and records which kind it was, so you can branch after decoding. It is the general-purpose union mechanism and imposes no constraints on what types are valid.

`StringOrSlice` and `StringOrObject` are the two higher-level union types. They decode directly into Go values rather than raw bytes, for the specific and common cases where an API returns either a string or a collection for the same key.

**`StringOrSlice[T any]`**

Decodes a JSON string or a JSON array of `T`. When the value is a string, `IsString` is true and `String` holds it. When it is an array, `IsString` is false and `Slice` holds the decoded elements.

```go
type StringOrSlice[T any] struct {
    IsString bool
    String   string
    Slice    []T
}

// Handles both:
//   "tags": "featured"
//   "tags": ["featured", "new", "sale"]
type Product struct {
    Tags jsondec.StringOrSlice[string] `json:"tags"`
}
```

**`StringOrObject[T any]`**

Decodes a JSON string or a JSON object into `T`. When the value is a string, `IsString` is true. When it is an object, `IsString` is false and `Object` holds the decoded struct.

```go
type StringOrObject[T any] struct {
    IsString bool
    String   string
    Object   T
}

// Handles both:
//   "author": "alice"
//   "author": {"id": 1, "name": "Alice"}
type Post struct {
    Author jsondec.StringOrObject[User] `json:"author"`
}
```

---

### Forbidden fields

**`Forbidden`**

When a field is typed `Forbidden`, decoding stops with `ErrForbiddenField` if that key appears in the JSON. Use this for fields that are known to exist in the wire format but must never be accepted — deprecated fields, privilege escalation vectors, or keys reserved for internal use.

```go
type CreateUserRequest struct {
    Name  string            `json:"name,required"`
    Email string            `json:"email,required"`
    Role  jsondec.Forbidden `json:"role"` // if this key appears, decoding fails — no caller may send it
}
```

`Forbidden` does not silently drop the field. It makes the entire decode call fail with `ErrForbiddenField` the moment that key is seen in the input. Use it for fields where accepting the value silently would be a security issue — privilege escalation vectors, deprecated fields that used to do something dangerous, or keys your validation layer has explicitly ruled out.

---

## Decoder options

`DecoderOptions` is passed to `RegisterDecoderOptions` and applies to every call made by the returned decoder. The zero value gives the same behaviour as `RegisterDecoder`.

```go
type DecoderOptions struct {
    DisallowUnknownFields bool
    MaxBytes              int
    MaxDepth              int
    MaxObjectFields       int
    MaxArrayLength        int
    ReuseInputBuffer      bool
}
```

### Strictness

**`DisallowUnknownFields bool`** — Default `false`. When true, any JSON key with no matching struct field causes decoding to stop with `ErrUnknownField`. When false, unknown keys are skipped. Enable this for internal APIs where an unexpected field indicates a client bug; leave it off for public APIs where forward compatibility matters.

### Structural limits

These limits protect against malicious or malformed input. They apply when the decoder is traversing portions of the document without decoding them: skipping unknown fields and preserving raw values. Nesting within decoded struct fields is not counted against `MaxDepth`.

**`MaxBytes int`** — Default 0 (disabled). Rejects the entire input document if its byte length exceeds this value, before any parsing begins. Also rejects any individual `RawValue`, `RawObject`, `RawArray`, or `RawUnion` field whose raw byte length exceeds this value at the point it is stored.

**`MaxDepth int`** — Default 0 (disabled). Rejects a value being skipped or preserved if its nesting depth exceeds this value. Prevents stack exhaustion from pathologically nested input.

**`MaxObjectFields int`** — Default 0 (disabled). Rejects a JSON object being skipped or preserved if it has more fields than this value.

**`MaxArrayLength int`** — Default 0 (disabled). Rejects a JSON array being skipped or preserved if it has more elements than this value.

### Memory

**`ReuseInputBuffer bool`** — Default `false`.

When `false` (the default), jsondec copies the input `[]byte` once before decoding into any type that can hold a reference to string or byte data — `string`, `[]byte`, `RawValue`, `RawObject`, `RawArray`, `RawUnion`, `map` keys, and `any`. This copy means decoded values are safe to use after the input buffer is modified or freed.

When `true`, decoded strings and `[]byte` fields point directly into the input slice — no copy is made. Two constraints follow: the caller must keep the input slice alive and unmodified for as long as any decoded value is in use, and jsondec may destructively modify the input bytes in place when unescaping strings containing backslash escape sequences.

---

## Supported types

| Go type | Accepted JSON | Notes |
|---|---|---|
| `bool` | `true`, `false` | |
| `int`, `int8`, `int16`, `int32`, `int64` | Number | Integer only; `ErrNumberOverflow` if out of range for the target width |
| `uint`, `uint8`, `uint16`, `uint32`, `uint64` | Number | Non-negative integer only |
| `uintptr` | Number | Decoded as `uint64` |
| `float32`, `float64` | Number | |
| `string` | String | |
| `[]byte` | String | Raw string bytes — **not** base64-decoded; see the note in [Why not encoding/json](#why-not-encodingjson) |
| `time.Time` | String | Must be RFC 3339 with nanoseconds (`time.RFC3339Nano`) |
| `json.Number` | Number | Preserved as the original string representation |
| Struct | Object | Fields matched by `json` tag, then Go field name |
| `*T` | Any or null | Null sets pointer to nil; non-null allocates T and decodes into it |
| `[]T` | Array or null | Null sets slice to nil |
| `[N]T` | Array | Input shorter than N zeroes remaining elements; longer returns `ErrArrayTooLong` |
| `map[string]V` | Object or null | Only string keys; null sets map to nil |
| `interface{}` | Any | Empty interface only — `interface{ SomeMethod() }` is not supported unless it also implements `json.Unmarshaler`. Objects → `map[string]interface{}`; arrays → `[]interface{}`; numbers → `float64` |
| `json.Unmarshaler` | Any | Raw bytes passed to `UnmarshalJSON` |
| `encoding.TextUnmarshaler` | String | Decoded string passed to `UnmarshalText`; null zeroes the value |

The following map types bypass reflection on every key and value assignment: `map[string]string`, `map[string]int`, `map[string]int64`, `map[string]uint64`, `map[string]float64`, `map[string]bool`.

---

## One-off decode functions

These functions compile and cache type information on first call. They are intended for decoding types you do not control (and therefore cannot register at startup), and for custom `json.Unmarshaler` implementations that need to delegate specific fields back to jsondec.

**`DecodeInto[T any](raw []byte, dst *T) error`**

Decodes `raw` into `dst` with default options.

**`DecodeIntoOptions[T any](raw []byte, dst *T, opts DecoderOptions) error`**

Decodes `raw` into `dst` with the given options.

**`DecodeObject[T any](raw []byte, dst *T) error`**

Decodes `raw` into `dst`. Returns `ErrExpectedObject` if `raw` is not a JSON object or null.

**`DecodeArray[T any](raw []byte, dst *[]T) error`**

Decodes `raw` into `dst`. Returns `ErrExpectedArray` if `raw` is not a JSON array or null.

**`DecodeString(raw []byte) (string, error)`**

Decodes `raw` as a JSON string. Returns `ErrTrailingData` if non-whitespace follows the closing quote.

**`DecodeStringSlice(raw []byte) ([]string, error)`**

Decodes `raw` as a JSON array of strings.

**`DecodeStringEnum(raw []byte, allowed ...string) (string, error)`**

Decodes `raw` as a JSON string and returns `ErrInvalidLiteral` if the value is not in `allowed`.

---

## Inspection functions

These read raw JSON bytes without decoding into Go types.

**`Kind(raw []byte) JSONKind`**

Returns the top-level kind of `raw` after skipping leading whitespace. Does not fully validate the value — `Kind` returning `KindObject` means the first non-whitespace byte is `{`, not that the object is well-formed.

**`Valid(raw []byte) bool`**

Reports whether `raw` is exactly one complete, valid JSON value with only whitespace following it. Full validation.

**`IsNull(raw []byte) bool`**, **`IsObject(raw []byte) bool`**, **`IsArray(raw []byte) bool`**

Convenience wrappers around `Kind`.

---

## Errors

### Runtime errors

All decode functions return `jsondec.Error` on failure.

```go
type Error struct {
    Code   ErrorCode
    Offset int    // byte position in the input where the error was detected
    Field  []byte // the field name being decoded when the error occurred, if known
    Path   string // dot-notation path to the field, if known
}
```

`Path` uses dot notation for nested struct fields and bracket notation for array indices and quoted field names: `"order.items[2].price"`, `"metadata[\"x-custom\"]"`. It is populated only when an error propagates up through at least one struct or array level — errors at the top level have an empty path.

To inspect the error code:

```go
var e jsondec.Error
if errors.As(err, &e) {
    switch e.Code {
    case jsondec.ErrRequiredFieldMissing:
        // e.Field contains the field name
        // e.Path contains the dot-notation path
    case jsondec.ErrUnknownField:
        // e.Field contains the unexpected key
    case jsondec.ErrValueTooLarge:
        // e.Offset is where the oversized value started
    }
}
```

### Compile errors

`RegisterDecoder` and `RegisterDecoderOptions` panic with `CompileError` if `T` cannot be compiled. This happens at startup, not at decode time.

```go
type CompileError struct {
    Type  reflect.Type // the type that failed
    Field string       // the struct field that caused the failure, if applicable
    Err   error        // the underlying reason
}
```

Common causes: unsupported field type, duplicate `json` field names in the same struct, more than 64 required fields.

### Error codes

| Code | Meaning |
|---|---|
| `ErrUnexpectedEOF` | Input ended before the value was complete |
| `ErrExpectedObject` | Expected `{` |
| `ErrExpectedArray` | Expected `[` |
| `ErrExpectedString` | Expected `"` |
| `ErrExpectedColon` | Expected `:` after an object key |
| `ErrExpectedCommaOrEnd` | Expected `,` or a closing bracket |
| `ErrInvalidString` | String contains a control character or invalid UTF-8 |
| `ErrInvalidEscape` | Unrecognised `\X` escape sequence |
| `ErrInvalidUnicodeEscape` | `\uXXXX` is malformed or forms an invalid surrogate pair |
| `ErrInvalidNumber` | Number is not valid JSON |
| `ErrNumberOverflow` | Number is out of range for the destination type |
| `ErrInvalidLiteral` | Unrecognised literal (not `true`, `false`, or `null`) |
| `ErrInvalidNull` | `null` appeared where the destination type does not accept it |
| `ErrRequiredFieldMissing` | A `,required` field was absent from the JSON object |
| `ErrArrayTooLong` | Array had more elements than the fixed-size Go array destination, or exceeded `MaxArrayLength` |
| `ErrTrailingData` | Non-whitespace bytes followed the top-level value |
| `ErrNilDestination` | `dst` was nil |
| `ErrUnsupportedType` | No decoder exists for the destination type |
| `ErrUnknownField` | Unknown key encountered with `DisallowUnknownFields` set |
| `ErrValueTooLarge` | Input or a raw field value exceeded `MaxBytes` |
| `ErrMaxDepth` | Nesting exceeded `MaxDepth` while skipping or preserving a value |
| `ErrObjectTooLarge` | Object exceeded `MaxObjectFields` while skipping or preserving |
| `ErrForbiddenField` | A key typed `Forbidden` appeared in the JSON object |
| `ErrExpectedStringOrArray` | `StringOrSlice` field received neither a string nor an array |
| `ErrExpectedStringOrObject` | `StringOrObject` field received neither a string nor an object |
