package objectify

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
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
	"github.com/spf13/pflag"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/errgroup"
	"gopkg.in/go-playground/validator.v9"
	"gopkg.in/yaml.v2"
	"hash/adler32"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	ttemplate "text/template"
	"time"
)

func init() {
	var err error
	validate = validator.New()
	logger, err = zap.NewDevelopment()
	if err != nil {
		log.Fatal(err.Error())
	}
}

var validate *validator.Validate
var logger *zap.Logger

//Handler is an empty struct used to carry useful utility functions
type Handler struct{}

func New() *Handler {
	return &Handler{}
}

//Function is a generic function that returns an error
type Function func() error

func (t *Handler) ToMap(obj interface{}) map[string]interface{} {
	struc := structs.New(obj)
	return struc.Map()
}

func (t *Handler) MarshalProto(msg proto.Message) []byte {
	output, _ := proto.Marshal(msg)
	return output
}

func (t *Handler) MarshalJSON(v interface{}) []byte {
	output, _ := json.MarshalIndent(v, "", "  ")
	return output
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
		log.Fatalf("%q should be set", envKey)
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

func (t *Handler) WrapErrf(err error, format, msg string) error {
	return errors.Wrapf(err, format, msg)
}

func (t *Handler) HumanizeTime(tim time.Time) string {
	return humanize.Time(tim)
}

func (t *Handler) MultiError(err error, list ...error) error {
	return multierror.Append(err, list...)
}

func (t *Handler) Log() *zap.Logger {
	return logger
}
func (t *Handler) ParsePFlags() {
	pflag.Parse()
}

func (t *Handler) ParseFlags() {
	flag.Parse()
}

func (t *Handler) Request(req *http.Request) (*http.Response, error) {
	return http.DefaultClient.Do(req)
}

func (t *Handler) Replace(content string, replacements ...string) string {
	rep := strings.NewReplacer(replacements...)
	return rep.Replace(content)
}
