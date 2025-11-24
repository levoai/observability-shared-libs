package spec_util

import (
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"

	"github.com/levoai/observability-shared-libs/test"
)

func TestGeneralizeWitness(t *testing.T) {
	type TestCase struct {
		name            string
		inputWitness    string
		expectedWitness string
		spec            string
	}
	testCases := make([]TestCase, 0)
	for i := 1; i <= 8; i++ {
		testCases = append(testCases, TestCase{
			name:            fmt.Sprintf("%d", i),
			inputWitness:    fmt.Sprintf("testdata/generalize_witnesses/gitlab.%d.concrete.pb.txt", i),
			expectedWitness: fmt.Sprintf("testdata/generalize_witnesses/gitlab.%d.generalized.pb.txt", i),
			spec:            "testdata/generalize_witnesses/spec.pb.txt",
		})
	}

	for _, c := range testCases {
		input := test.LoadWitnessFromFileOrDile(c.inputWitness)
		expected := test.LoadWitnessFromFileOrDile(c.expectedWitness)
		spec := test.LoadAPISpecFromFileOrDie(c.spec)

		pathMatchers := GetPathRegexps(spec)
		output, err := GeneralizeWitness(pathMatchers, input)
		assert.Nil(t, err, fmt.Sprintf("[%s] error generalizing witness", c.name))
		assert.Equal(
			t,
			proto.MarshalTextString(expected),
			proto.MarshalTextString(output),
			fmt.Sprintf("[%s] generalized witness not equal to expected", c.name),
		)
	}
}

func TestPathRegexps(t *testing.T) {
	testCases := []struct {
		name string
		path string
		// Maps concrete path to number of matches (1 + # path parameters)
		shouldMatch    map[string]int
		shouldNotMatch []string
	}{
		{
			name: "no parameters",
			path: "/v1/foo",
			shouldMatch: map[string]int{
				"/v1/foo": 1,
			},
			shouldNotMatch: []string{"/v1/bar"},
		},
		{
			name: "two parameters",
			path: "/v1/{arg1}/foo/{myarg}",
			shouldMatch: map[string]int{
				"/v1/x1/foo/x2":    3,
				"/v1/x1.x2/foo/x2": 3,
			},
			shouldNotMatch: []string{
				"/v1/bar",
				"/v1/{arg1}/foo/{myarg}",
				"/foo/foo",
				"/v1/foo/foo/bar/baz",
				"/v1/x1/bar/x2",
			},
		},
		{
			name: "two parameters, trailing slash",
			path: "/v1/{arg1}/foo/{myarg}/",
			shouldMatch: map[string]int{
				"/v1/x1/foo/x2":    3,
				"/v1/x1.x2/foo/x2": 3,
			},
			shouldNotMatch: []string{
				"/v1/bar",
				"/v1/{arg1}/foo/{myarg}",
				"/foo/foo",
				"/v1/foo/foo/bar/baz",
				"/v1/x1/bar/x2",
			},
		},
		{
			name: "no trailing parameter",
			path: "/v1/{arg1}/foo",
			shouldMatch: map[string]int{
				"/v1/x1/foo":    2,
				"/v1/x1.x2/foo": 2,
			},
			shouldNotMatch: []string{
				"/v1/bar",
				"/v1/{arg1}/foo",
				"/v1/foo/foo/bar/baz",
				"/v1/x1/bar/x2",
			},
		},
		{
			name: "empty path",
			path: "/",
			shouldMatch: map[string]int{
				"": 1,
			},
			shouldNotMatch: []string{
				"/",
				"/v1",
			},
		},
	}

	for _, c := range testCases {
		regexes := getPathRegexps([]string{c.path})
		for r, _ := range regexes {
			for path, count := range c.shouldMatch {
				match := r.FindStringSubmatch(path)
				assert.Equal(t, count, len(match), fmt.Sprintf("[%s] '%s' didn't match", c.name, path))
			}
			for _, path := range c.shouldNotMatch {
				match := r.FindStringSubmatch(path)
				assert.Equal(t, 0, len(match), fmt.Sprintf("[%s] '%s' matched but should not have", c.name, path))
			}
		}
	}
}
