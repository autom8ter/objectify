package objectify

import (
	"bufio"
	"context"
	"crypto/rand"
	"github.com/spf13/cobra"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"github.com/Masterminds/sprig"
	"github.com/dustin/go-humanize"
	"github.com/fatih/structs"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	"github.com/hashicorp/go-multierror"
	"github.com/joho/godotenv"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/errgroup"
	"golang.org/x/text/language"
	"google.golang.org/grpc"
	"gopkg.in/go-playground/validator.v9"
	"gopkg.in/yaml.v2"
	"hash/adler32"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"syscall"
	ttemplate "text/template"
	"time"
)

func init() {
	validate = validator.New()
	logger = logrus.New()
}

type Option func(h *logrus.Logger) *logrus.Logger

var validate *validator.Validate
var logger *logrus.Logger

//Handler is an empty struct used to carry useful utility functions
type Handler struct {
	logger *logrus.Entry
}

func New(opts ...Option) *Handler {
	for _, o := range opts {
		logger = o(logger)
	}
	return &Handler{
		logger: logrus.NewEntry(logger),
	}
}

func Default() *Handler {
	logger.Formatter = &logrus.JSONFormatter{PrettyPrint: true}
	logger.Out = os.Stdout
	logger.Level = logrus.DebugLevel
	e := logrus.NewEntry(logger)
	return &Handler{
		logger: e,
	}
}

//Function is a generic function that returns an error
type Function func() error

func (t *Handler) ToMap(obj interface{}) map[string]interface{} {
	struc := structs.New(obj)
	return struc.Map()
}

func (t *Handler) ToAnnotations(obj interface{}) map[string]string {
	rtrn := make(map[string]string)
	for k, v := range t.ToMap(obj) {
		rtrn[k] = string(t.MarshalJSON(v))
	}
	return rtrn
}

func (t *Handler) MarshalProto(msg proto.Message) []byte {
	output, _ := proto.Marshal(msg)
	return output
}

func (t *Handler) MarshalJSON(v interface{}) []byte {
	output, _ := json.MarshalIndent(v, "", "  ")
	return output
}

func (t *Handler) Attributes(obj interface{})map[string]string {
	m := t.ToMap(obj)
	newm := make(map[string]string)
	for k,v := range m {
		newm[k]=string(t.MarshalJSON(v))
	}
	m["type"] =reflect.TypeOf(obj).String()
	m["value"] =reflect.ValueOf(obj).String()
	m["kind"] =reflect.TypeOf(obj).Kind().String()
	return newm
}

func (t *Handler) UnmarshalFromConfig(file string, obj interface{}) error {
	bits, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	bits = t.MarshalJSON(bits)
	err = json.Unmarshal(bits, obj)
	if err != nil {
		return err
	}
	return nil
}

func (t *Handler) MarshalYAML(obj interface{}) []byte {
	output, _ := yaml.Marshal(obj)
	return output
}

func (t *Handler) GetEnv(envKey, defaultValue string) string {
	val := os.Getenv(envKey)
	if val == "" {
		val = defaultValue
	}
	if val == "" {
		t.Fatalf("%q should be set", envKey)
	}
	return val
}

func (t *Handler) MustGetEnv(envKey string) string {
	val := os.Getenv(envKey)
	if val == "" {
		panic(errors.New("value not found in environment for: " + envKey))
	}
	return val
}

func (t *Handler) MarshalXML(obj interface{}) []byte {
	output, _ := xml.Marshal(obj)
	return output
}

func (t *Handler) RenderHTML(text string, obj interface{}, w io.Writer) error {
	tmpl, err := template.New("").Funcs(sprig.GenericFuncMap()).Parse(text)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, obj)
}

func (t *Handler) RenderTXT(text string, obj interface{}, w io.Writer) error {
	tmpl, err := ttemplate.New("").Funcs(sprig.GenericFuncMap()).Parse(text)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, obj)
}

func (t *Handler) Validate(data interface{}) error {
	t.PanicIfNil(data)
	return validate.Struct(data)
}

func (t *Handler) UUID() string {
	return uuid.New().String()
}

func (t *Handler) HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password must not be empty")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return string(hash[:]), err
	}
	return string(hash[:]), nil
}

func (t *Handler) ComparePasswordToHash(hashed string, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
}

func (t *Handler) Prompt(question string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(question)
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)
	text = strings.TrimRight(text, "`")
	text = strings.TrimLeft(text, "`")
	if strings.Contains(text, "?") {
		newtext := strings.Split(text, "?")
		text = newtext[0]
	}
	return text
}

func (t *Handler) Base64Encode(str string) string {
	return base64.StdEncoding.EncodeToString([]byte(str))
}

func (t *Handler) Base64Decode(str string) string {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return ""
	}
	return string(data)
}

func (t *Handler) Base64EncodeRaw(str []byte) string {
	return base64.StdEncoding.EncodeToString(str)
}

func (t *Handler) Base64DecodeRaw(str string) []byte {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil
	}
	return data
}

func (t *Handler) RegexMatch(regex string, s string) bool {
	match, _ := regexp.MatchString(regex, s)
	return match
}

func (t *Handler) RegexFindAll(regex string, s string, n int) []string {
	r := regexp.MustCompile(regex)
	return r.FindAllString(s, n)
}

func (t *Handler) RegexFind(regex string, s string) string {
	r := regexp.MustCompile(regex)
	return r.FindString(s)
}

func (t *Handler) RegexReplaceAll(regex string, s string, repl string) string {
	r := regexp.MustCompile(regex)
	return r.ReplaceAllString(s, repl)
}

func (t *Handler) RegexReplaceAllLiteral(regex string, s string, repl string) string {
	r := regexp.MustCompile(regex)
	return r.ReplaceAllLiteralString(s, repl)
}

func (t *Handler) RegexSplit(regex string, s string, n int) []string {
	r := regexp.MustCompile(regex)
	return r.Split(s, n)
}

func (t *Handler) Sha256sum(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

func (t *Handler) Sha1sum(input string) string {
	hash := sha1.Sum([]byte(input))
	return hex.EncodeToString(hash[:])
}

func (t *Handler) Adler32sum(input string) string {
	hash := adler32.Checksum([]byte(input))
	return fmt.Sprintf("%d", hash)
}

func (t *Handler) Run(ctx context.Context, funcs ...Function) error {
	g, ctx := errgroup.WithContext(ctx)
	for _, f := range funcs {
		g.Go(f)
	}
	return g.Wait()
}

func (t *Handler) Shell(cmd string) string {
	e := exec.Command("/bin/sh", "-c", cmd)
	e.Env = os.Environ()
	res, _ := e.Output()
	return strings.TrimSpace(string(res))
}

func (t *Handler) Bash(cmd string) string {
	e := exec.Command("/bin/bash", "-c", cmd)
	e.Env = os.Environ()
	res, _ := e.Output()
	return strings.TrimSpace(string(res))
}

func (t *Handler) Python3(cmd string) string {
	e := exec.Command("python3", "-c", cmd)
	e.Env = os.Environ()
	res, _ := e.Output()
	return strings.TrimSpace(string(res))
}

func (t *Handler) RandomToken(length int) []byte {
	b := make([]byte, length)
	rand.Read(b)
	return b
}

func (t *Handler) DotEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func (t *Handler)  RootCmd(name, description string, fn func() error) *cobra.Command {
	c := &cobra.Command{
		Use:  name,
		Long: description,
	}
	if fn != nil {
		c.Run = func(cmd *cobra.Command, args []string) {
			if err := fn(); err != nil {
				Util.Fatalln(err.Error())
			}
		}
	}
	return c
}

func (t *Handler) HumanizeTime(tim time.Time) string {
	return humanize.Time(tim)
}

func (t *Handler) MultiError(err error, list ...error) error {
	return multierror.Append(err, list...)
}

func (t *Handler) ParsePFlags() {
	pflag.Parse()
}

func (t *Handler) ParseFlags() {
	flag.Parse()
}

func (t *Handler) GetLogger() *logrus.Logger {
	return logger
}

func (t *Handler) Request(req *http.Request) (*http.Response, error) {
	return http.DefaultClient.Do(req)
}

func (t *Handler) Replace(content string, replacements ...string) string {
	rep := strings.NewReplacer(replacements...)
	return rep.Replace(content)
}

func (t *Handler) ReadAsCSV(val string) ([]string, error) {
	if val == "" {
		return []string{}, nil
	}
	stringReader := strings.NewReader(val)
	csvReader := csv.NewReader(stringReader)
	return csvReader.Read()
}

func (t *Handler) ParseLang(msg string) (language.Tag, error) {
	return language.Parse(msg)
}

func (t *Handler) MustParseLang(msg string) language.Tag {
	return language.MustParse(msg)
}

func (t *Handler) ParseRegion(msg string) (language.Region, error) {
	return language.ParseRegion(msg)
}

func (t *Handler) MustParseRegion(msg string) language.Region {
	return language.MustParseRegion(msg)
}

func (t *Handler) Dial(address string) (net.Conn, error) {
	return net.Dial("tcp", address)
}

func (t *Handler) MustDial(address string) net.Conn {
	conn, err := t.Dial(address)
	if err != nil {
		panic(err.Error())
	}
	return conn
}

func (t *Handler) MustDialGRPC(address string, opts ...grpc.DialOption) *grpc.ClientConn {
	conn, err := grpc.Dial(address, opts...)
	if err != nil {
		panic(err.Error())
	}
	return conn
}

func (e *Handler) WatchForShutdown(ctx context.Context, fn func()) error {
	sdCh := make(chan os.Signal, 1)
	defer close(sdCh)
	defer signal.Stop(sdCh)
	signal.Notify(sdCh, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sdCh:
		e.Debug("signal received shutting down]", "time", e.HumanizeTime(time.Now()))
		fn()
	case <-ctx.Done():
		// no-op
	}
	return nil
}

func (t *Handler) PanicIfNil(obj interface{}) {
	typ := reflect.TypeOf(obj)
	if obj == nil {
		panic(fmt.Sprintf("nil object name: %s path: %s", typ.Name(), typ.PkgPath()))
	}
}

func (t *Handler) WrapErrf(err error, format, msg string) error {
	return errors.Wrapf(err, format, msg)
}

func (t *Handler) WrapErr(err error, msg string) error {
	return errors.Wrap(err, msg)
}

func (t *Handler) Warn(args ...interface{}) {
	t.logger.Warn(args...)
}

func (t *Handler) Warnln(args ...interface{}) {
	t.logger.Warnln(args...)
}

func (t *Handler) Warnf(format string, args ...interface{}) {
	t.logger.Warnf(format, args...)
}

func (t *Handler) Fatal(args ...interface{}) {
	t.logger.Fatal(args...)
}

func (t *Handler) Fatalln(args ...interface{}) {
	t.logger.Fatalln(args...)
}

func (t *Handler) Fatalf(format string, args ...interface{}) {
	t.logger.Fatalf(format, args...)
}

func (t *Handler) DebugErr(err error, args ...interface{}) {
	t.logger.Debug(err.Error(), args)
}

func (t *Handler) Debug(args ...interface{}) {
	t.logger.Debug(args...)
}

func (t *Handler) Debugln(args ...interface{}) {
	t.logger.Debugln(args...)
}

func (t *Handler) Debugf(format string, args ...interface{}) {
	t.logger.Fatalf(format, args...)
}

func (t *Handler) FatalErr(err error, msg string) {
	t.logger.Fatal(msg, err.Error())
}

func (t *Handler) WarnErr(err error, msg string) {
	t.logger.Warn(msg, err.Error())
}

func (t *Handler) Entry() *logrus.Entry {
	return t.logger
}

func (t *Handler) ReplaceEntry(entry *logrus.Entry) {
	t.logger = entry
}

func (t *Handler) Context() context.Context {
	return context.TODO()
}

func (t *Handler) ToContext(ctx context.Context, key interface{}, val interface{}) context.Context {
	return context.WithValue(ctx, key, val)
}

func (t *Handler) FromContext(ctx context.Context, key string) interface{} {
	return ctx.Value(key)
}

func (t *Handler) Sort(list []string) []string {
	sort.Strings(list)
	return list
}

// Index returns the first index of the target string t, or -1 if no match is found.
func (h *Handler) Index(vs []string, t string) int {
	for i, v := range vs {
		if v == t {
			return i
		}
	}
	return -1
}

//Contains returns true if the target string t is in the slice.
func (h *Handler) Contains(vs []string, t string) bool {
	return h.Index(vs, t) >= 0
}

//Filter returns a new slice containing all strings in the slice that satisfy the predicate f.
func (h *Handler) Filter(vs []string, f func(string) bool) []string {
	vsf := make([]string, 0)
	for _, v := range vs {
		if f(v) {
			vsf = append(vsf, v)
		}
	}
	return vsf
}

func (h *Handler) ModifyString(vs []string, f func(string) string) []string {
	vsm := make([]string, len(vs))
	for i, v := range vs {
		vsm[i] = f(v)
	}
	return vsm
}

func (h *Handler) Callbacks(obj interface{}, callbacks ...CallbackFunc) error {
	for _, c := range callbacks {
		if err := c(obj)(); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) Callback(obj interface{}, f CallbackFunc) error {
	return f(obj)()
}

type CallbackFunc func(interface{}) func() error

// TypeSafe returns true if the src is the type named in target.
func (h *Handler) TypeSafe(target string, src interface{}) bool {
	return target == typeOf(src)
}

func typeOf(src interface{}) string {
	return fmt.Sprintf("%T", src)
}
