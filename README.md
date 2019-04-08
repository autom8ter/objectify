# objectify
--
    import "github.com/autom8ter/objectify"


## Usage

#### type Function

```go
type Function func() error
```

Function is a generic function that returns an error

#### type Handler

```go
type Handler struct{}
```

Handler is an empty struct used to carry useful utility functions

#### func  New

```go
func New() *Handler
```

#### func (*Handler) Adler32sum

```go
func (t *Handler) Adler32sum(input string) string
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

#### func (*Handler) Debug

```go
func (t *Handler) Debug(msg string, key, val string)
```

#### func (*Handler) DebugErr

```go
func (t *Handler) DebugErr(err error, msg string)
```

#### func (*Handler) DebugObject

```go
func (t *Handler) DebugObject(obj interface{}, msg string)
```

#### func (*Handler) Dial

```go
func (t *Handler) Dial(address string) (net.Conn, error)
```

#### func (*Handler) DotEnv

```go
func (t *Handler) DotEnv()
```

#### func (*Handler) FatalErr

```go
func (t *Handler) FatalErr(err error, msg string)
```

#### func (*Handler) FromContext

```go
func (t *Handler) FromContext(ctx context.Context, key string) interface{}
```

#### func (*Handler) GetEnv

```go
func (t *Handler) GetEnv(envKey, defaultValue string) string
```

#### func (*Handler) HashPassword

```go
func (t *Handler) HashPassword(password string) (string, error)
```

#### func (*Handler) HumanizeTime

```go
func (t *Handler) HumanizeTime(tim time.Time) string
```

#### func (*Handler) Log

```go
func (t *Handler) Log() *zap.Logger
```

#### func (*Handler) MarshalJSON

```go
func (t *Handler) MarshalJSON(v interface{}) []byte
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

#### func (*Handler) MultiError

```go
func (t *Handler) MultiError(err error, list ...error) error
```

#### func (*Handler) MustDial

```go
func (t *Handler) MustDial(address string) net.Conn
```

#### func (*Handler) MustDialGRPC

```go
func (t *Handler) MustDialGRPC(address string, opts ...grpc.DialOption) *grpc.ClientConn
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

#### func (*Handler) NewContext

```go
func (t *Handler) NewContext() context.Context
```

#### func (*Handler) ParseFlags

```go
func (t *Handler) ParseFlags()
```

#### func (*Handler) ParseLang

```go
func (t *Handler) ParseLang(msg string) (language.Tag, error)
```

#### func (*Handler) ParsePFlags

```go
func (t *Handler) ParsePFlags()
```

#### func (*Handler) ParseRegion

```go
func (t *Handler) ParseRegion(msg string) (language.Region, error)
```

#### func (*Handler) Prompt

```go
func (t *Handler) Prompt(question string) string
```

#### func (*Handler) Python3

```go
func (t *Handler) Python3(cmd string) string
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
func (t *Handler) RenderHTML(text string, obj interface{}, w io.Writer) error
```

#### func (*Handler) RenderTXT

```go
func (t *Handler) RenderTXT(text string, obj interface{}, w io.Writer) error
```

#### func (*Handler) Replace

```go
func (t *Handler) Replace(content string, replacements ...string) string
```

#### func (*Handler) Request

```go
func (t *Handler) Request(req *http.Request) (*http.Response, error)
```

#### func (*Handler) Run

```go
func (t *Handler) Run(ctx context.Context, funcs ...Function) error
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

#### func (*Handler) ToContext

```go
func (t *Handler) ToContext(ctx context.Context, key string, val interface{}) context.Context
```

#### func (*Handler) ToMap

```go
func (t *Handler) ToMap(obj interface{}) map[string]interface{}
```

#### func (*Handler) UUID

```go
func (t *Handler) UUID() string
```

#### func (*Handler) UnmarshalFromConfig

```go
func (t *Handler) UnmarshalFromConfig(file string, obj interface{}) error
```

#### func (*Handler) Validate

```go
func (t *Handler) Validate(data interface{}) error
```

#### func (*Handler) WarnErr

```go
func (t *Handler) WarnErr(err error, msg string)
```

#### func (*Handler) WrapErrf

```go
func (t *Handler) WrapErrf(err error, format, msg string) error
```
