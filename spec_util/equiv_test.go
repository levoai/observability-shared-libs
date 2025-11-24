package spec_util

import (
	"testing"

	"github.com/andreyvit/diff"
	"github.com/golang/protobuf/proto"

	pb "github.com/akitasoftware/akita-ir/go/api_spec"
	"github.com/levoai/observability-shared-libs/test"
)

// Primitives
var (
	fixedStringFoo = &pb.Primitive{
		Value: &pb.Primitive_StringValue{
			StringValue: &pb.String{
				Type: &pb.StringType{
					FixedValues: []string{"foo"},
				},
				Value: "foo",
			},
		},
	}
	fixedStringBar = &pb.Primitive{
		Value: &pb.Primitive_StringValue{
			StringValue: &pb.String{
				Type: &pb.StringType{
					FixedValues: []string{"bar"},
				},
				Value: "bar",
			},
		},
	}
	nonFixedStringFoo = &pb.Primitive{
		Value: &pb.Primitive_StringValue{
			StringValue: &pb.String{
				Value: "foo",
			},
		},
	}
	nonFixedStringBar = &pb.Primitive{
		Value: &pb.Primitive_StringValue{
			StringValue: &pb.String{
				Value: "bar",
			},
		},
	}
	fixedInt123 = &pb.Primitive{
		Value: &pb.Primitive_Int32Value{
			Int32Value: &pb.Int32{
				Type: &pb.Int32Type{
					FixedValues: []int32{123},
				},
				Value: 123,
			},
		},
	}
)

var (
	structWithFixedStringFoo = &pb.Struct{
		Fields: map[string]*pb.Data{
			"common_field": &pb.Data{
				Value: &pb.Data_Primitive{fixedStringFoo},
			},
		},
	}
	listWithFixedStringFoo = &pb.List{
		Elems: []*pb.Data{
			&pb.Data{
				Value: &pb.Data_Primitive{fixedStringFoo},
			},
		},
	}
)

func hashPrimitiveOrDie(p *pb.Primitive) string {
	if h, err := hashPrimitive(p); err != nil {
		panic(err)
	} else {
		return h
	}
}

func makeEquivChecker() *equivChecker {
	return &equivChecker{
		lToRPrimitiveMap: make(map[string]*pb.Primitive),
		rToLPrimitiveMap: make(map[string]*pb.Primitive),
	}
}

func TestContainsFixedValue(t *testing.T) {
	testCases := []struct {
		name      string
		isFixed   bool
		primitive *pb.Primitive
	}{
		{
			name:      "Fixed value matched",
			isFixed:   true,
			primitive: fixedStringFoo,
		},
		{
			name:    "Fixed value no match",
			isFixed: false,
			primitive: &pb.Primitive{
				Value: &pb.Primitive_StringValue{
					StringValue: &pb.String{
						Type: &pb.StringType{
							FixedValues: []string{"abc"},
						},
						Value: "def",
					},
				},
			},
		},
		{
			name:      "No fixed value",
			isFixed:   false,
			primitive: nonFixedStringFoo,
		},
		{
			name:    "bool is always fixed",
			isFixed: true,
			primitive: &pb.Primitive{
				Value: &pb.Primitive_BoolValue{
					BoolValue: &pb.Bool{
						Type: &pb.BoolType{
							// Intentionally leave out FixedValues. It should not matter.
						},
						Value: false,
					},
				},
			},
		},
	}

	for _, c := range testCases {
		r := containsFixedValue(c.primitive)
		if c.isFixed != r {
			t.Errorf("[%s] expected: %v got: %v", c.name, c.isFixed, r)
		}
	}
}

func TestEquivalentPrimitives(t *testing.T) {
	testCases := []struct {
		name     string
		expectEq bool
		chk      *equivChecker // optional
		p1       *pb.Primitive
		p2       *pb.Primitive
	}{
		{
			name: "user-type mismatch",
			p1: &pb.Primitive{
				TypeHint: "foo",
			},
			p2: &pb.Primitive{
				TypeHint: "bar",
			},
		},
		{
			name: "fixed value and non-fixed value",
			p1:   fixedStringFoo,
			p2:   nonFixedStringFoo,
		},
		{
			name: "fixed value type mismatch",
			p1:   fixedStringFoo,
			p2:   fixedInt123,
		},
		{
			name: "fixed value mismatch",
			p1:   fixedStringFoo,
			p2:   fixedStringBar,
		},
		{
			name:     "fixed value match",
			expectEq: true,
			p1:       fixedStringFoo,
			p2:       fixedStringFoo,
		},
		{
			name:     "non-fixed value bijection - empty state",
			expectEq: true,
			p1:       nonFixedStringFoo,
			p2:       nonFixedStringBar,
		},
		{
			name:     "non-fixed value bijection - non-empty state",
			expectEq: true,
			chk: &equivChecker{
				lToRPrimitiveMap: map[string]*pb.Primitive{
					hashPrimitiveOrDie(nonFixedStringFoo): nonFixedStringBar,
				},
				rToLPrimitiveMap: map[string]*pb.Primitive{
					hashPrimitiveOrDie(nonFixedStringBar): nonFixedStringFoo,
				},
			},
			p1: nonFixedStringFoo,
			p2: nonFixedStringBar,
		},
		{
			name:     "non-fixed value not bijection",
			expectEq: false,
			chk: &equivChecker{
				lToRPrimitiveMap: map[string]*pb.Primitive{
					// Intentionally map nonFixedStringFoo to something different.
					hashPrimitiveOrDie(nonFixedStringFoo): fixedInt123,
				},
				rToLPrimitiveMap: map[string]*pb.Primitive{
					hashPrimitiveOrDie(nonFixedStringBar): nonFixedStringFoo,
				},
			},
			p1: nonFixedStringFoo,
			p2: nonFixedStringBar,
		},
		{
			name:     "bijection does not apply to bool",
			expectEq: false,
			p1: &pb.Primitive{
				Value: &pb.Primitive_BoolValue{
					BoolValue: &pb.Bool{
						Value: true,
					},
				},
			},
			p2: &pb.Primitive{
				Value: &pb.Primitive_BoolValue{
					BoolValue: &pb.Bool{
						Value: false,
					},
				},
			},
		},
	}

	for _, c := range testCases {
		if c.chk == nil {
			c.chk = makeEquivChecker()
		}
		if eq, err := c.chk.equivalentPrimitives(c.p1, c.p2); err != nil {
			t.Errorf("[%s] got unexpected error", c.name)
		} else if eq != c.expectEq {
			t.Errorf("[%s] expected %v, got %v", c.name, c.expectEq, eq)
		}
	}
}

func TestEquivalentStructs(t *testing.T) {
	testCases := []struct {
		name     string
		expectEq bool
		s1       *pb.Struct
		s2       *pb.Struct
	}{
		{
			name: "different fields",
			s1:   structWithFixedStringFoo,
			s2: &pb.Struct{
				Fields: map[string]*pb.Data{
					"different_field": &pb.Data{
						Value: &pb.Data_Primitive{fixedStringFoo},
					},
				},
			},
		},
		{
			name: "same field different value",
			s1:   structWithFixedStringFoo,
			s2: &pb.Struct{
				Fields: map[string]*pb.Data{
					"common_field": &pb.Data{
						Value: &pb.Data_Primitive{fixedStringBar},
					},
				},
			},
		},
		{
			name:     "same field same value",
			expectEq: true,
			s1:       structWithFixedStringFoo,
			s2:       structWithFixedStringFoo,
		},
	}

	for _, c := range testCases {
		chk := makeEquivChecker()
		if eq, err := chk.equivalentStructs(c.s1, c.s2); err != nil {
			t.Errorf("[%s] unexpected error: %v", c.name, err)
		} else if eq != c.expectEq {
			t.Errorf("[%s] expected %v, got %v", c.name, c.expectEq, eq)
		}
	}
}

func TestEquivalentLists(t *testing.T) {
	testCases := []struct {
		name     string
		expectEq bool
		l1       *pb.List
		l2       *pb.List
	}{
		{
			name: "different num elems",
			l1:   listWithFixedStringFoo,
			l2: &pb.List{
				Elems: []*pb.Data{
					&pb.Data{
						Value: &pb.Data_Primitive{fixedStringFoo},
					},
					&pb.Data{
						Value: &pb.Data_Primitive{fixedStringFoo},
					},
				},
			},
		},
		{
			name: "elem not equiv",
			l1:   listWithFixedStringFoo,
			l2: &pb.List{
				Elems: []*pb.Data{
					&pb.Data{
						Value: &pb.Data_Primitive{fixedStringBar},
					},
				},
			},
		},
		{
			name:     "identical",
			expectEq: true,
			l1:       listWithFixedStringFoo,
			l2:       listWithFixedStringFoo,
		},
	}

	for _, c := range testCases {
		chk := makeEquivChecker()
		if eq, err := chk.equivalentLists(c.l1, c.l2); err != nil {
			t.Errorf("[%s] unexpected error: %v", c.name, err)
		} else if eq != c.expectEq {
			t.Errorf("[%s] expected %v, got %v", c.name, c.expectEq, eq)
		}
	}
}

func TestEquivalentOptionals(t *testing.T) {
	testCases := []struct {
		name     string
		expectEq bool
		o1       *pb.Optional
		o2       *pb.Optional
	}{
		{
			name:     "both optional",
			expectEq: true,
			o1: &pb.Optional{
				Value: &pb.Optional_Data{
					&pb.Data{
						Value: &pb.Data_Primitive{nonFixedStringFoo},
					},
				},
			},
			o2: &pb.Optional{
				Value: &pb.Optional_Data{
					&pb.Data{
						Value: &pb.Data_Primitive{nonFixedStringBar},
					},
				},
			},
		},
		{
			name:     "both none",
			expectEq: true,
			o1: &pb.Optional{
				Value: &pb.Optional_None{},
			},
			o2: &pb.Optional{
				Value: &pb.Optional_None{},
			},
		},
		{
			name: "mismatch",
			o1: &pb.Optional{
				Value: &pb.Optional_None{},
			},
			o2: &pb.Optional{
				Value: &pb.Optional_Data{
					&pb.Data{
						Value: &pb.Data_Primitive{fixedStringFoo},
					},
				},
			},
		},
	}

	for _, c := range testCases {
		chk := makeEquivChecker()
		if eq, err := chk.equivalentOptionals(c.o1, c.o2); err != nil {
			t.Errorf("[%s] unexpected error: %v", c.name, err)
		} else if eq != c.expectEq {
			t.Errorf("[%s] expected %v, got %v", c.name, c.expectEq, eq)
		}
	}
}

func TestEquivalentDataTemplates(t *testing.T) {
	testCases := []struct {
		name              string
		expectEq          bool
		dataTemplate1File string
		dataTemplate2File string
	}{
		{
			name:              "identical constants",
			expectEq:          true,
			dataTemplate1File: "fixed_string_constant_1.pb.txt",
			dataTemplate2File: "fixed_string_constant_1.pb.txt",
		},
		{
			name:              "fixed constant and constant ref",
			expectEq:          true,
			dataTemplate1File: "fixed_string_constant_1.pb.txt",
			dataTemplate2File: "ref_fixed_string_constant_1.pb.txt",
		},
		{
			name:              "identical constant ref",
			expectEq:          true,
			dataTemplate1File: "ref_fixed_string_constant_1.pb.txt",
			dataTemplate2File: "ref_fixed_string_constant_1.pb.txt",
		},
		{
			name:              "fixed and non-fixed values",
			dataTemplate1File: "fixed_string_constant_1.pb.txt",
			dataTemplate2File: "ref_string_constant_2.pb.txt",
		},
		{
			name:              "non-fixed strings equiv",
			expectEq:          true,
			dataTemplate1File: "string_constant_2.pb.txt",
			dataTemplate2File: "ref_string_constant_2.pb.txt",
		},
		{
			name:              "user type mismatch",
			dataTemplate1File: "string_constant_2.pb.txt",
			dataTemplate2File: "ref_string_constant_4.pb.txt",
		},
		{
			name:              "bijection match",
			expectEq:          true,
			dataTemplate1File: "bijection_1_1.pb.txt",
			dataTemplate2File: "bijection_1_2.pb.txt",
		},
		{
			name:              "bijection mismatch",
			dataTemplate1File: "bijection_1_1.pb.txt",
			dataTemplate2File: "bijection_2.pb.txt",
		},
		{
			name:              "bijection nested struct match",
			expectEq:          true,
			dataTemplate1File: "bijection_nested_struct_1.pb.txt",
			dataTemplate2File: "bijection_nested_struct_2.pb.txt",
		},
		{
			name:              "bijection nested struct mismatch",
			expectEq:          false,
			dataTemplate1File: "bijection_nested_struct_1.pb.txt",
			dataTemplate2File: "bijection_nested_struct_mismatch.pb.txt",
		},
		{
			name:              "identical ref",
			expectEq:          true,
			dataTemplate1File: "ref_response_1.pb.txt",
			dataTemplate2File: "ref_response_1.pb.txt",
		},
		{
			name:              "different ref",
			dataTemplate1File: "ref_response_1.pb.txt",
			dataTemplate2File: "ref_fixed_string_constant_1.pb.txt",
		},
		{
			name:              "indirect ref to constant",
			expectEq:          true,
			dataTemplate1File: "indirect_ref_to_consant_1.pb.txt",
			dataTemplate2File: "indirect_ref_to_consant_2.pb.txt",
		},
		{
			name:              "full struct ref to struct with ref",
			expectEq:          true,
			dataTemplate1File: "full_struct_ref_with_ref_1.pb.txt",
			dataTemplate2File: "full_struct_ref_with_ref_2.pb.txt",
		},
		//
		// Struct templates
		//
		{
			name:              "struct template equiv",
			expectEq:          true,
			dataTemplate1File: "struct_template_1_no_ref.pb.txt",
			dataTemplate2File: "struct_template_1_with_ref.pb.txt",
		},
		{
			name:              "struct template different fields",
			dataTemplate1File: "struct_template_1_no_ref.pb.txt",
			dataTemplate2File: "struct_template_1_diff_field_name.pb.txt",
		},
		{
			name:              "struct template different field value",
			dataTemplate1File: "struct_template_1_no_ref.pb.txt",
			dataTemplate2File: "struct_template_1_diff_ref.pb.txt",
		},
		//
		// List templates
		//
		{
			name:              "list template equiv",
			expectEq:          true,
			dataTemplate1File: "list_template_1_no_ref.pb.txt",
			dataTemplate2File: "list_template_1_with_ref.pb.txt",
		},
		{
			name:              "list template different num elements",
			dataTemplate1File: "list_template_1_with_ref.pb.txt",
			dataTemplate2File: "list_template_1_extra_elem.pb.txt",
		},
		{
			name:              "list template different elem value",
			dataTemplate1File: "struct_template_1_no_ref.pb.txt",
			dataTemplate2File: "struct_template_1_diff_ref.pb.txt",
		},
		//
		// Optional templates
		//
		{
			name:              "optional template constant and ref match",
			expectEq:          true,
			dataTemplate1File: "optional_string_constant_2.pb.txt",
			dataTemplate2File: "optional_ref_string_constant_2.pb.txt",
		},
		{
			name:              "optional template and non-optional template",
			dataTemplate1File: "ref_string_constant_2.pb.txt",
			dataTemplate2File: "optional_ref_string_constant_2.pb.txt",
		},
	}

	for _, c := range testCases {
		prefix := test.LoadSequenceFromFileOrDie(prefixSeqFile).MethodTemplates
		dt1 := test.LoadDataTemplateFromFileOrDie("testdata/equiv/" + c.dataTemplate1File)
		dt2 := test.LoadDataTemplateFromFileOrDie("testdata/equiv/" + c.dataTemplate2File)
		if eq, err := EquivalentDataTemplates(prefix, dt1, dt2); err != nil {
			t.Errorf("[%s] got unexpected error: %v:", c.name, err)
		} else if eq != c.expectEq {
			t.Errorf("[%s] expected %v, got %v", c.name, c.expectEq, eq)
		}
	}
}

func TestUnrollDataTemplate(t *testing.T) {
	testCases := []struct {
		name                     string
		dataTemplateFile         string
		expectedDataTemplateFile string
	}{
		{
			name:                     "ref in struct template",
			dataTemplateFile:         "ref_string_constant_2.pb.txt",
			expectedDataTemplateFile: "string_constant_2.pb.txt",
		},
	}
	for _, c := range testCases {
		prefix := test.LoadSequenceFromFileOrDie(prefixSeqFile).MethodTemplates
		dt := test.LoadDataTemplateFromFileOrDie("testdata/equiv/" + c.dataTemplateFile)
		if result, err := unrollDataTemplate(prefix, dt); err != nil {
			t.Errorf("[%s] unexpected error: %v", c.name, err)
		} else {
			expected := test.LoadDataTemplateFromFileOrDie("testdata/equiv/" + c.expectedDataTemplateFile)
			if !proto.Equal(result, expected) {
				t.Errorf("[%s] expectation didn't match: %v", c.name, diff.LineDiff(proto.MarshalTextString(expected), proto.MarshalTextString(result)))
			}
		}
	}
}
