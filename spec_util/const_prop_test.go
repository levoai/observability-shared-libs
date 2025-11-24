package spec_util

import (
	"testing"

	"github.com/andreyvit/diff"
	"github.com/golang/protobuf/proto"

	"github.com/levoai/observability-shared-libs/test"
)

const (
	testdataPathPrefix = "testdata/const_prop/"
	prefixSeqFile      = "testdata/prefix_seq.pb.txt"
)

func TestPropagateConstants(t *testing.T) {
	testCases := []struct {
		name                 string
		inputTemplateFile    string
		expectedTemplateFile string
		expectErr            bool
	}{
		{
			name:              "Ref method index out of bounds",
			inputTemplateFile: "input/ref_method_out_of_bounds.pb.txt",
			expectErr:         true,
		},
		{
			name:              "Constants",
			inputTemplateFile: "input/constants.pb.txt",
			// Expect no change because all arguments are constants already.
			expectedTemplateFile: "input/constants.pb.txt",
		},
		{
			name:                 "Ref top-level constants",
			inputTemplateFile:    "input/ref_top_level_const.pb.txt",
			expectedTemplateFile: "expected/ref_top_level_const.pb.txt",
		},
		{
			name:              "Ref response constants",
			inputTemplateFile: "input/ref_response.pb.txt",
			// Expect no change because response can't be a constant.
			expectedTemplateFile: "input/ref_response.pb.txt",
		},
		{
			name:                 "Nested refs",
			inputTemplateFile:    "input/nested_refs.pb.txt",
			expectedTemplateFile: "expected/nested_refs.pb.txt",
		},
		{
			name:                 "Ref field in constant",
			inputTemplateFile:    "input/ref_field_in_const.pb.txt",
			expectedTemplateFile: "expected/ref_field_in_const.pb.txt",
		},
		//
		// Structs
		//
		{
			name:                 "Propagate const into struct field",
			inputTemplateFile:    "input/propagate_into_struct.pb.txt",
			expectedTemplateFile: "expected/propagate_into_struct.pb.txt",
		},
		{
			name:                 "Upgrade struct with all constant fields to constant",
			inputTemplateFile:    "input/upgrade_struct_to_const.pb.txt",
			expectedTemplateFile: "expected/upgrade_struct_to_const.pb.txt",
		},
		{
			name:                 "Ref constant field in struct with mixed fields",
			inputTemplateFile:    "input/ref_const_field_in_mixed_struct.pb.txt",
			expectedTemplateFile: "expected/ref_const_field_in_mixed_struct.pb.txt",
		},
		{
			name:              "Ref non-constant field in struct with mixed fields",
			inputTemplateFile: "input/ref_non_const_field_in_mixed_struct.pb.txt",
			// Expect no change because the reference points to a non-constant field.
			expectedTemplateFile: "input/ref_non_const_field_in_mixed_struct.pb.txt",
		},
		{
			name:              "Full struct ref to struct with mixed fields",
			inputTemplateFile: "input/full_struct_ref_to_mixed_struct.pb.txt",
			// Expect no change because the struct contains non-constant fields.
			expectedTemplateFile: "input/full_struct_ref_to_mixed_struct.pb.txt",
		},
		{
			name:                 "Full struct ref to struct with all const ref fields",
			inputTemplateFile:    "input/full_struct_ref_to_struct_with_all_const_refs.pb.txt",
			expectedTemplateFile: "expected/full_struct_ref_to_struct_with_all_const_refs.pb.txt",
		},
		{
			name:              "Ref missing field in struct",
			inputTemplateFile: "input/ref_struct_missing_field.pb.txt",
			expectErr:         true,
		},
		//
		// Lists
		//
		{
			name:                 "Propagate const into list elem",
			inputTemplateFile:    "input/propagate_into_list.pb.txt",
			expectedTemplateFile: "expected/propagate_into_list.pb.txt",
		},
		{
			name:                 "Upgrade list with all constant elems to constant",
			inputTemplateFile:    "input/upgrade_list_to_const.pb.txt",
			expectedTemplateFile: "expected/upgrade_list_to_const.pb.txt",
		},
		{
			name:                 "Ref constant elem in list with mixed elems",
			inputTemplateFile:    "input/ref_const_elem_in_mixed_list.pb.txt",
			expectedTemplateFile: "expected/ref_const_elem_in_mixed_list.pb.txt",
		},
		{
			name:              "Ref non-constant elem in list with mixed elems",
			inputTemplateFile: "input/ref_non_const_elem_in_mixed_list.pb.txt",
			// Expect no change because the reference points to a non-constant elem.
			expectedTemplateFile: "input/ref_non_const_elem_in_mixed_list.pb.txt",
		},
		{
			name:              "Full list ref to list with mixed elems",
			inputTemplateFile: "input/full_list_ref_to_mixed_list.pb.txt",
			// Expect no change because the struct contains non-constant fields.
			expectedTemplateFile: "input/full_list_ref_to_mixed_list.pb.txt",
		},
		{
			name:                 "Full list ref to list with all const ref elems",
			inputTemplateFile:    "input/full_list_ref_to_list_with_all_const_refs.pb.txt",
			expectedTemplateFile: "expected/full_list_ref_to_list_with_all_const_refs.pb.txt",
		},
		{
			name:              "List elem ref index out of bounds",
			inputTemplateFile: "input/ref_list_out_of_bounds.pb.txt",
			expectErr:         true,
		},
		//
		// Optional
		//
		{
			name:              "Constants with optional template",
			inputTemplateFile: "input/optional_constants.pb.txt",
			// Expect no change because all arguments are constants already.
			expectedTemplateFile: "input/optional_constants.pb.txt",
		},
		{
			name:                 "Ref top-level constants in optional templates",
			inputTemplateFile:    "input/optional_ref_top_level_const.pb.txt",
			expectedTemplateFile: "expected/optional_ref_top_level_const.pb.txt",
		},
		{
			name:              "Ref response constants in optional template",
			inputTemplateFile: "input/optional_ref_response.pb.txt",
			// Expect no change because response can't be a constant.
			expectedTemplateFile: "input/optional_ref_response.pb.txt",
		},
		{
			name:                 "Ref in optional template to missing arg",
			inputTemplateFile:    "input/optional_ref_missing.pb.txt",
			expectedTemplateFile: "expected/optional_ref_missing.pb.txt",
		},
	}

	for _, c := range testCases {
		prefix := test.LoadSequenceFromFileOrDie(prefixSeqFile).MethodTemplates
		template := test.LoadMethodTemplateFromFileOrDie(testdataPathPrefix + c.inputTemplateFile)
		if err := PropagateConstants(prefix, template); err != nil {
			if !c.expectErr {
				t.Errorf("[%s] got unexpected error: %v", c.name, err)
			}
		} else if c.expectErr {
			t.Errorf("[%s] expected error, didn't get one", c.name)
		} else {
			expected := test.LoadMethodTemplateFromFileOrDie(testdataPathPrefix + c.expectedTemplateFile)
			if !proto.Equal(template, expected) {
				t.Errorf("[%s] did not get expected MethodTemplate after constant propagation:\n%s",
					c.name, diff.LineDiff(proto.MarshalTextString(expected), proto.MarshalTextString(template)))
			}
		}
	}
}
