package spec_util

import (
	"testing"

	"github.com/golang/protobuf/proto"

	pb "github.com/akitasoftware/akita-ir/go/api_spec"
	"github.com/levoai/observability-shared-libs/test"
)

const (
	toyMethodsPath = "testdata/ref_map/toy_methods.pb.txt"
)

func TestHasRefs(t *testing.T) {
	testCases := []struct {
		methodsPath  string
		name         string
		dID          DataTypeID
		expectHasRef bool
	}{
		{
			methodsPath:  toyMethodsPath,
			name:         "request type in method_1",
			dID:          DataTypeID("user_type_1"),
			expectHasRef: true,
		},
		{
			methodsPath:  toyMethodsPath,
			name:         "nested request type in method_1",
			dID:          DataTypeID("user_type_2"),
			expectHasRef: true,
		},
		{
			methodsPath:  toyMethodsPath,
			name:         "optional request type in method_1",
			dID:          DataTypeID("user_type_3"),
			expectHasRef: true,
		},
		{
			methodsPath:  toyMethodsPath,
			name:         "list response type",
			dID:          DataTypeID("user_type_4"),
			expectHasRef: true,
		},
		{
			methodsPath: toyMethodsPath,
			name:        "non-free response",
			dID:         DataTypeID("user_type_5"),
			// We should still generate reference to "non-free" response.
			// TODO: Remove is_free annotations from response.
			// https://app.asana.com/0/1131596442939587/1136991798543849
			expectHasRef: true,
		},
		{
			methodsPath: "testdata/ref_map/non_free_arg_method.pb.txt",
			name:        "non-free argument",
			dID:         DataTypeID("user_type_1"),
			// Should not generate references to non-free arg.
			expectHasRef: false,
		},
		{
			methodsPath: toyMethodsPath,
			name:        "single fixed value argument",
			dID:         DataTypeID("single_fixed_value_arg"),
			// Should not generate references to single fixed value type.
			expectHasRef: false,
		},
		{
			methodsPath: toyMethodsPath,
			name:        "single fixed value response",
			dID:         DataTypeID("single_fixed_value_response"),
			// Should not generate references to single fixed value type.
			expectHasRef: false,
		},
		{
			methodsPath:  toyMethodsPath,
			name:         "invalid data type ID",
			dID:          DataTypeID("not-a-real-data-type-id"),
			expectHasRef: false,
		},
		{
			methodsPath:  toyMethodsPath,
			name:         "no ref to error response",
			dID:          DataTypeID("error_response_type_1"),
			expectHasRef: false,
		},
	}

	for _, c := range testCases {
		calls := test.LoadMethodCallsFromFileOrDie(c.methodsPath)
		refMap := NewRefMap(calls.Calls)

		if refMap.HasRefs(c.dID) {
			if !c.expectHasRef {
				t.Errorf("[%s] did not expect to have ref to data ID %s, got hasRef=true", c.name, c.dID)
			}
		} else {
			if c.expectHasRef {
				t.Errorf("[%s] expected to have ref to data ID %s, got hasRef=false", c.name, c.dID)
			}
		}
	}
}

func TestGetDataRefs(t *testing.T) {
	testCases := []struct {
		name             string
		dID              DataTypeID
		expectedRefFiles []string
	}{
		{
			name: "request primitive",
			dID:  DataTypeID("user_type_1"),
			// The call to method_2 contains an argument of type user_type_1,
			// but it's not free, so we don't include a reference to the
			// second call's argument.
			expectedRefFiles: []string{
				"testdata/ref_map/index_0_method_1_arg_1_ref.pb.txt",
			},
		},
		{
			name: "request struct",
			dID:  DataTypeID("user_type_3"),
			expectedRefFiles: []string{
				"testdata/ref_map/index_0_method_1_arg_2_ref.pb.txt",
			},
		},
		{
			name: "response primitive",
			dID:  DataTypeID("user_type_5"),
			expectedRefFiles: []string{
				"testdata/ref_map/index_1_method_2_200_response_ref_field1.pb.txt",
			},
		},
		{
			name: "response list",
			dID:  DataTypeID("user_type_4"),
			expectedRefFiles: []string{
				"testdata/ref_map/index_0_method_1_200_response_ref.pb.txt",
				"testdata/ref_map/index_1_method_2_200_response_ref_field2.pb.txt",
			},
		},
	}

	for _, c := range testCases {
		calls := test.LoadMethodCallsFromFileOrDie(toyMethodsPath)
		refMap := NewRefMap(calls.Calls)
		refs := refMap.GetDataRefs(c.dID, nil)

		expectedRefs := make([]*pb.MethodDataRef, len(c.expectedRefFiles))
		for i, p := range c.expectedRefFiles {
			expectedRefs[i] = test.LoadMethodDataRefFromFileOrDie(p)
		}

		if len(refs) != len(expectedRefs) {
			t.Errorf("[%s] expected %d refs, got %d", c.name, len(expectedRefs), len(refs))
		} else {
			for _, ref := range refs {
				matched := false
				for _, expectedRef := range expectedRefs {
					if proto.Equal(ref, expectedRef) {
						matched = true
						break
					}
				}
				if !matched {
					t.Errorf("[%s] got unexpected ref: %v", c.name, ref)
				}
			}
		}
	}
}
