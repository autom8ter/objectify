# objectify
--
    import "github.com/autom8ter/objectify"


## Usage

#### type Handler

```go
type Handler struct {
}
```

Handler is an empty struct used to carry useful utility functions

#### func  Default

```go
func Default() *Handler
```

#### func (*Handler) Adler32sum

```go
func (t *Handler) Adler32sum(input string) string
```

#### func (*Handler) Attributes

```go
func (t *Handler) Attributes(obj interface{}) map[string]string
```

#### func (*Handler) Base64Decode

```go
func (t *Handler) Base64Decode(str string) string
```

#### func (*Handler) Base64DecodeRaw

```go
func (t *Handler) Base64DecodeRaw(str string) []byte
```

#### func (*Handler) Base64Encode

```go
func (t *Handler) Base64Encode(str string) string
```

#### func (*Handler) Base64EncodeRaw

```go
func (t *Handler) Base64EncodeRaw(str []byte) string
```

#### func (*Handler) Bash

```go
func (t *Handler) Bash(cmd string) string
```

#### func (*Handler) ComparePasswordToHash

```go
func (t *Handler) ComparePasswordToHash(hashed string, password string) error
```

#### func (*Handler) Contains

```go
func (h *Handler) Contains(vs []string, t string) bool
```
Contains returns true if the target string t is in the slice.

#### func (*Handler) Context

```go
func (t *Handler) Context() context.Context
```

#### func (*Handler) ConvertDurationPB

```go
func (t *Handler) ConvertDurationPB(d *duration.Duration) (time.Duration, error)
```

#### func (*Handler) Debugf

```go
func (t *Handler) Debugf(format string, args ...interface{})
```

#### func (*Handler) DeepEqual

```go
func (h *Handler) DeepEqual(this interface{}, that interface{}) bool
```

#### func (*Handler) Dial

```go
func (t *Handler) Dial(address string) (net.Conn, error)
```

#### func (*Handler) DotEnv

```go
func (t *Handler) DotEnv()
```

#### func (*Handler) EnvPrompt

```go
func (t *Handler) EnvPrompt(key string) (string, error)
```

#### func (*Handler) Fatalf

```go
func (t *Handler) Fatalf(format string, args ...interface{})
```

#### func (*Handler) Filter

```go
func (h *Handler) Filter(vs []string, f func(string) bool) []string
```
Filter returns a new slice containing all strings in the slice that satisfy the
predicate f.

#### func (*Handler) FromContext

```go
func (t *Handler) FromContext(ctx context.Context, key string) interface{}
```

#### func (*Handler) GetEnv

```go
func (t *Handler) GetEnv(envKey, defaultValue string) string
```

#### func (*Handler) GetLogger

```go
func (t *Handler) GetLogger() *logrus.Logger
```

#### func (*Handler) HashPassword

```go
func (t *Handler) HashPassword(password string) (string, error)
```

#### func (*Handler) HumanizeTime

```go
func (t *Handler) HumanizeTime(tim time.Time) string
```

#### func (*Handler) Index

```go
func (h *Handler) Index(vs []string, t string) int
```
Index returns the first index of the target string t, or -1 if no match is
found.

#### func (*Handler) MarshalAnyPB

```go
func (t *Handler) MarshalAnyPB(msg proto.Message) (*any.Any, error)
```

#### func (*Handler) MarshalJSON

```go
func (t *Handler) MarshalJSON(v interface{}) []byte
```

#### func (*Handler) MarshalJSONPB

```go
func (t *Handler) MarshalJSONPB(msg proto.Message) []byte
```

#### func (*Handler) MarshalProto

```go
func (t *Handler) MarshalProto(msg proto.Message) []byte
```

#### func (*Handler) MarshalXML

```go
func (t *Handler) MarshalXML(obj interface{}) []byte
```

#### func (*Handler) MarshalYAML

```go
func (t *Handler) MarshalYAML(obj interface{}) []byte
```

#### func (*Handler) MatchesPB

```go
func (t *Handler) MatchesPB(d *any.Any, msg proto.Message) bool
```

#### func (*Handler) MessageNamePB

```go
func (t *Handler) MessageNamePB(d *any.Any) (string, error)
```

#### func (*Handler) ModifyString

```go
func (h *Handler) ModifyString(vs []string, f func(string) string) []string
```

#### func (*Handler) MultiError

```go
func (t *Handler) MultiError(err error, list ...error) error
```

#### func (*Handler) MustDial

```go
func (t *Handler) MustDial(address string) net.Conn
```

#### func (*Handler) MustGetEnv

```go
func (t *Handler) MustGetEnv(envKey string) string
```

#### func (*Handler) MustParseLang

```go
func (t *Handler) MustParseLang(msg string) language.Tag
```

#### func (*Handler) MustParseRegion

```go
func (t *Handler) MustParseRegion(msg string) language.Region
```

#### func (*Handler) NewError

```go
func (t *Handler) NewError(msg string) error
```

#### func (*Handler) PanicIfNil

```go
func (t *Handler) PanicIfNil(obj interface{})
```

#### func (*Handler) Parse

```go
func (t *Handler) Parse(tmpl *template.Template, pattern string) (*template.Template, error)
```

#### func (*Handler) ParseFiles

```go
func (t *Handler) ParseFiles(tmpl *template.Template, names ...string) (*template.Template, error)
```

#### func (*Handler) ParseLang

```go
func (t *Handler) ParseLang(msg string) (language.Tag, error)
```

#### func (*Handler) ParseRegion

```go
func (t *Handler) ParseRegion(msg string) (language.Region, error)
```

#### func (*Handler) ParseText

```go
func (t *Handler) ParseText(tmpl *template.Template, text string) (*template.Template, error)
```

#### func (*Handler) Printf

```go
func (t *Handler) Printf(format string, args ...interface{})
```

#### func (*Handler) Prompt

```go
func (t *Handler) Prompt(question string) string
```

#### func (*Handler) Python3

```go
func (t *Handler) Python3(cmd string) string
```

#### func (*Handler) RandomString

```go
func (h *Handler) RandomString(size int) string
```

#### func (*Handler) RandomToken

```go
func (t *Handler) RandomToken(length int) []byte
```

#### func (*Handler) ReadAsCSV

```go
func (t *Handler) ReadAsCSV(val string) ([]string, error)
```

#### func (*Handler) RegexFind

```go
func (t *Handler) RegexFind(regex string, s string) string
```

#### func (*Handler) RegexFindAll

```go
func (t *Handler) RegexFindAll(regex string, s string, n int) []string
```

#### func (*Handler) RegexMatch

```go
func (t *Handler) RegexMatch(regex string, s string) bool
```

#### func (*Handler) RegexReplaceAll

```go
func (t *Handler) RegexReplaceAll(regex string, s string, repl string) string
```

#### func (*Handler) RegexReplaceAllLiteral

```go
func (t *Handler) RegexReplaceAllLiteral(regex string, s string, repl string) string
```

#### func (*Handler) RegexSplit

```go
func (t *Handler) RegexSplit(regex string, s string, n int) []string
```

#### func (*Handler) RenderHTML

```go
func (t *Handler) RenderHTML(tmpl *template.Template, obj interface{}, w io.Writer) error
```

#### func (*Handler) RenderTXT

```go
func (t *Handler) RenderTXT(tmpl *template.Template, obj interface{}, w io.Writer) error
```

#### func (*Handler) Replace

```go
func (t *Handler) Replace(content string, replacements ...string) string
```

#### func (*Handler) Request

```go
func (t *Handler) Request(req *http.Request) (*http.Response, error)
```

#### func (*Handler) Sha1sum

```go
func (t *Handler) Sha1sum(input string) string
```

#### func (*Handler) Sha256sum

```go
func (t *Handler) Sha256sum(input string) string
```

#### func (*Handler) Shell

```go
func (t *Handler) Shell(cmd string) string
```

#### func (*Handler) Sort

```go
func (t *Handler) Sort(list []string) []string
```

#### func (*Handler) TimestampNow

```go
func (t *Handler) TimestampNow() *timestamp.Timestamp
```

#### func (*Handler) TimestampPB

```go
func (t *Handler) TimestampPB(stamp *timestamp.Timestamp) (time.Time, error)
```

#### func (*Handler) TimestampProto

```go
func (h *Handler) TimestampProto(t time.Time) (*timestamp.Timestamp, error)
```

#### func (*Handler) TimestampString

```go
func (t *Handler) TimestampString(stamp *timestamp.Timestamp) string
```

#### func (*Handler) ToContext

```go
func (t *Handler) ToContext(ctx context.Context, key interface{}, val interface{}) context.Context
```

#### func (*Handler) ToMap

```go
func (t *Handler) ToMap(obj interface{}) map[string]interface{}
```

#### func (*Handler) TypeSafe

```go
func (h *Handler) TypeSafe(target string, src interface{}) bool
```
TypeSafe returns true if the src is the type named in target.

#### func (*Handler) UUID

```go
func (t *Handler) UUID() string
```

#### func (*Handler) UnarshalAnyPB

```go
func (t *Handler) UnarshalAnyPB(a *any.Any, msg proto.Message) error
```

#### func (*Handler) UnmarshalFromConfig

```go
func (t *Handler) UnmarshalFromConfig(file string, obj interface{}) error
```

#### func (*Handler) UnmarshalJSON

```go
func (t *Handler) UnmarshalJSON(bits []byte, msg proto.Message) error
```

#### func (*Handler) UnmarshalProto

```go
func (t *Handler) UnmarshalProto(bits []byte, msg proto.Message) error
```

#### func (*Handler) UnmarshalXML

```go
func (t *Handler) UnmarshalXML(bits []byte, msg proto.Message) error
```

#### func (*Handler) UnmarshalYAML

```go
func (t *Handler) UnmarshalYAML(bits []byte, msg proto.Message) error
```

#### func (*Handler) Validate

```go
func (t *Handler) Validate(data interface{}) error
```

#### func (*Handler) Warnf

```go
func (t *Handler) Warnf(format string, args ...interface{})
```

#### func (*Handler) WatchForShutdown

```go
func (e *Handler) WatchForShutdown(ctx context.Context, fn func()) error
```

#### func (*Handler) WrapErr

```go
func (t *Handler) WrapErr(err error, msg string) error
```

#### func (*Handler) WrapErrf

```go
func (t *Handler) WrapErrf(err error, format string, args ...interface{}) error
```
