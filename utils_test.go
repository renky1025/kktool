package kktool

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodePassword(t *testing.T) {
	encodestr := "$2a$10$aEJmlK/rNb.eRdfEznIjWOpAqnxRQXFtSoRkQ1LCN8uGU2NLrVt.S"
	//$2a$10$XIvO3YoqjAYSHz2GeIt7y.MKNTCoVBnEnXjA8kigGsKqPO4bnniwK
	pwdOk := "12345678"
	r := ComparePassword(encodestr, pwdOk)
	fmt.Println(r)
	require.True(t, r)
}

func TestHideStar(t *testing.T) {
	res := HideStar("13666666666")
	target := "136****6666"
	fmt.Println(res)
	assert.Equal(t, target, res)
}

func TestImage2Webp(t *testing.T) {
	Image2Webp("./images/Gitlab.jpeg", "./images/Gitlab.webp", 0.8)
	_, err := os.Stat("./images/Gitlab.webp")
	res := errors.Is(err, os.ErrNotExist)
	assert.True(t, res == false)
}
