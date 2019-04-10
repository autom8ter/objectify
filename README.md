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
type Handler struct {
}
```

Handler is an empty struct used to carry useful utility functions

#### func  Default

```go
func Default() *Handler
```

#### func  New

```go
func New(opts ...Option) *Handler
```

#### func  NewWithContextKey

```go
func NewWithContextKey(ctx context.Context, key string, opts ...Option) *Handler
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

#### func (*Handler) Context

```go
func (t *Handler) Context() context.Context
```

#### func (*Handler) Debug

```go
func (t *Handler) Debug(args ...interface{})
```

#### func (*Handler) DebugErr

```go
func (t *Handler) DebugErr(err error, args ...interface{})
```

#### func (*Handler) Debugf

```go
func (t *Handler) Debugf(format string, args ...interface{})
```

#### func (*Handler) Debugln

```go
func (t *Handler) Debugln(args ...interface{})
```

#### func (*Handler) Dial

```go
func (t *Handler) Dial(address string) (net.Conn, error)
```

#### func (*Handler) DotEnv

```go
func (t *Handler) DotEnv()
```

#### func (*Handler) Entry

```go
func (t *Handler) Entry() *logrus.Entry
```

#### func (*Handler) Fatal

```go
func (t *Handler) Fatal(args ...interface{})
```

#### func (*Handler) FatalErr

```go
func (t *Handler) FatalErr(err error, msg string)
```

#### func (*Handler) Fatalf

```go
func (t *Handler) Fatalf(format string, args ...interface{})
```

#### func (*Handler) Fatalln

```go
func (t *Handler) Fatalln(args ...interface{})
```

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

#### func (*Handler) PanicIfNil

```go
func (t *Handler) PanicIfNil(obj interface{})
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

#### func (*Handler) ReplaceEntry

```go
func (t *Handler) ReplaceEntry(entry *logrus.Entry)
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

#### func (*Handler) ToAnnotations

```go
func (t *Handler) ToAnnotations(obj interface{}) map[string]string
```

#### func (*Handler) ToContext

```go
func (t *Handler) ToContext(ctx context.Context, key interface{}, val interface{}) context.Context
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

#### func (*Handler) Warn

```go
func (t *Handler) Warn(args ...interface{})
```

#### func (*Handler) WarnErr

```go
func (t *Handler) WarnErr(err error, msg string)
```

#### func (*Handler) Warnf

```go
func (t *Handler) Warnf(format string, args ...interface{})
```

#### func (*Handler) Warnln

```go
func (t *Handler) Warnln(args ...interface{})
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
func (t *Handler) WrapErrf(err error, format, msg string) error
```

#### type Option

```go
type Option func(h *logrus.Logger) *logrus.Logger
```


#### func  Noop

```go
func Noop() Option
```

#### func  WithContext

```go
func WithContext(ctx context.Context) Option
```

#### func  WithDebugLevel

```go
func WithDebugLevel() Option
```

#### func  WithError

```go
func WithError(err error) Option
```

#### func  WithErrorLevel

```go
func WithErrorLevel() Option
```

#### func  WithFatalLevel

```go
func WithFatalLevel() Option
```

#### func  WithInfoLevel

```go
func WithInfoLevel() Option
```

#### func  WithJSONFormatter

```go
func WithJSONFormatter() Option
```

#### func  WithLevelFromEnv

```go
func WithLevelFromEnv(key string) Option
```

#### func  WithTextFormatter

```go
func WithTextFormatter(color bool) Option
```

#### func  WithWarnLevel

```go
func WithWarnLevel() Option
```

#### func  WithWriter

```go
func WithWriter(w io.Writer) Option
```
