package objectify_test

import (
	"bytes"
	"context"
	"fmt"
	"github.com/autom8ter/objectify"
	"testing"
)

var ctx = context.WithValue(context.Background(), "greeting", "hello")
var buffer = bytes.NewBuffer([]byte{})

var util = objectify.New(
	objectify.WithContext(ctx),
	objectify.WithWriter(buffer),
	objectify.WithWarnLevel(),
	objectify.WithJSONFormatter(),
)

func TestNew(t *testing.T) {
	util.Warnln("hello", "world")
	util.Warnln("greeting", util.FromContext(ctx, "greeting"))
	fmt.Println(buffer.String())
}
