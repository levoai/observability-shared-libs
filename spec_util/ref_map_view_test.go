package spec_util

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	pb "github.com/akitasoftware/akita-ir/go/api_spec"
	"github.com/levoai/observability-shared-libs/test"
)

const (
	toyMethods2Path = "testdata/ref_map/toy_methods2.pb.txt"
)

var (
	diffArgsOptions = []cmp.Option{
		cmp.Comparer(proto.Equal),
		cmpopts.SortSlices(func(d1, d2 *pb.Data) bool {
			return proto.MarshalTextString(d1) < proto.MarshalTextString(d2)
		}),
	}

	p1 = &pb.Primitive{
		Value:            &pb.Primitive_StringValue{&pb.String{}},
		AkitaAnnotations: &pb.AkitaAnnotations{IsFree: true},
	}
	p2 = &pb.Primitive{
		Value:            &pb.Primitive_StringValue{&pb.String{}},
		AkitaAnnotations: &pb.AkitaAnnotations{IsFree: false},
	}
	p3 = &pb.Primitive{
		Value:            &pb.Primitive_BoolValue{&pb.Bool{}},
		AkitaAnnotations: &pb.AkitaAnnotations{IsFree: true},
	}

	meta1 = &pb.DataMeta{
		Meta: &pb.DataMeta_Http{
			&pb.HTTPMeta{
				Location: &pb.HTTPMeta_Query{&pb.HTTPQuery{Key: "arg1"}},
			},
		},
	}
)

func mkPrimitive(p *pb.Primitive, meta *pb.DataMeta) *pb.Data {
	return &pb.Data{Value: &pb.Data_Primitive{p}, Meta: meta}
}

func mkStruct(fields map[string]*pb.Data, meta *pb.DataMeta) *pb.Data {
	return &pb.Data{Value: &pb.Data_Struct{&pb.Struct{Fields: fields}}, Meta: meta}
}

func TestGetDataRefsFromRefMapView(t *testing.T) {
	testCases := []struct {
		name             string
		dID              DataTypeID
		expectedRefFiles []string
	}{
		{
			name: "don't include reference to another reference",
			dID:  DataTypeID("user_type_1"),
			// The call to method_2 contains an argument of type user_type_1,
			// but it's a reference to the argument in the first call to method_1, so
			// we don't include a reference to the second call's argument.
			expectedRefFiles: []string{
				"testdata/ref_map/index_0_method_1_arg_1_ref.pb.txt",
			},
		},
		{
			name: "response references always useful",
			dID:  DataTypeID("user_type_4"),
			// References to response values are always considered useful, so we
			// should get 2 references: 1 to the response of the first call, 1 to the
			// response of the second call.
			expectedRefFiles: []string{
				"testdata/ref_map/index_0_method_1_200_response_ref.pb.txt",
				"testdata/ref_map/index_1_method_2_200_response_ref_field2.pb.txt",
			},
		},
	}

	methodTemplateFiles := []string{"testdata/ref_map/toy_method_1_template_1.pb.txt", "testdata/ref_map/toy_method_2_template_1.pb.txt"}
	for _, c := range testCases {
		calls := test.LoadMethodCallsFromFileOrDie(toyMethods2Path)
		refMap := NewRefMap(calls.Calls)
		methodTemplates := make([]*pb.MethodTemplate, len(methodTemplateFiles))
		for i, f := range methodTemplateFiles {
			methodTemplates[i] = test.LoadMethodTemplateFromFileOrDie(f)
		}
		view := NewRefMapView(refMap, methodTemplates)

		refs := view.GetDataRefs(c.dID, nil)
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

func TestGetFillableArgsOptional(t *testing.T) {
	arg := &pb.Data{
		Value: &pb.Data_Optional{
			Optional: &pb.Optional{
				Value: &pb.Optional_Data{
					Data: &pb.Data{
						Value: &pb.Data_Primitive{
							Primitive: &pb.Primitive{
								TypeHint: "bool_type",
								Value: &pb.Primitive_BoolValue{
									&pb.Bool{},
								},
							},
						},
					},
				},
			},
		},
	}

	// The empty refMap should not affect GetFillableArgs on an optional arg.
	v := NewRefMapView(NewRefMap([]*pb.Method{}), []*pb.MethodTemplate{})
	if diff := cmp.Diff([]*pb.Data{arg}, v.GetFillableArgs(arg), diffArgsOptions...); diff != "" {
		t.Errorf("Expected to be able to fill optional arg, got diff:\n%s", diff)
	}
}

func TestGetFillableArgs(t *testing.T) {
	testCases := []struct {
		name string
		arg  *pb.Data
	}{
		{
			name: "primitive",
			arg: &pb.Data{
				Value: &pb.Data_Primitive{
					Primitive: &pb.Primitive{
						TypeHint: "user_type_2",
						Value: &pb.Primitive_BoolValue{
							&pb.Bool{},
						},
					},
				},
			},
		},
		{
			name: "struct",
			arg: &pb.Data{
				Value: &pb.Data_Struct{
					Struct: &pb.Struct{
						Fields: map[string]*pb.Data{
							"field1": &pb.Data{
								Value: &pb.Data_Primitive{
									Primitive: &pb.Primitive{
										TypeHint: "user_type_1",
										Value: &pb.Primitive_StringValue{
											&pb.String{},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "list",
			arg: &pb.Data{
				Value: &pb.Data_List{
					List: &pb.List{
						Elems: []*pb.Data{
							&pb.Data{
								Value: &pb.Data_Primitive{
									Primitive: &pb.Primitive{
										TypeHint: "user_type_3",
										Value: &pb.Primitive_Int32Value{
											&pb.Int32{},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	methodTemplateFiles := []string{"testdata/ref_map/toy_method_1_template_1.pb.txt", "testdata/ref_map/toy_method_2_template_1.pb.txt"}
	for _, c := range testCases {
		calls := test.LoadMethodCallsFromFileOrDie(toyMethods2Path)
		methodTemplates := make([]*pb.MethodTemplate, len(methodTemplateFiles))
		for i, f := range methodTemplateFiles {
			methodTemplates[i] = test.LoadMethodTemplateFromFileOrDie(f)
		}

		v := NewRefMapView(NewRefMap(calls.Calls), methodTemplates)

		if diff := cmp.Diff([]*pb.Data{c.arg}, v.GetFillableArgs(c.arg), diffArgsOptions...); diff != "" {
			t.Errorf("[%s] Expected to be able to fill args, found diff:\n%s", c.name, diff)
		}
	}
}

func TestGetFillableArgsFree(t *testing.T) {
	arg := &pb.Data{
		Value: &pb.Data_Primitive{
			Primitive: &pb.Primitive{
				TypeHint: "bool_type",
				AkitaAnnotations: &pb.AkitaAnnotations{
					IsFree: true,
				},
				Value: &pb.Primitive_BoolValue{
					&pb.Bool{},
				},
			},
		},
	}

	// The empty refMap should not affect GetFillableArgs on a free arg.
	v := NewRefMapView(NewRefMap([]*pb.Method{}), []*pb.MethodTemplate{})
	if diff := cmp.Diff([]*pb.Data{arg}, v.GetFillableArgs(arg), diffArgsOptions...); diff != "" {
		t.Errorf("Expected to be able to fill free arg, got diff:\n%s", diff)
	}
}

// A non-free arg with multiple fixed values is not fillable.
func TestGetFillableArgsNonFreeArgWithMultipleFixedValues(t *testing.T) {
	arg := &pb.Data{
		Value: &pb.Data_Primitive{
			Primitive: &pb.Primitive{
				TypeHint: "string_type",
				Value: &pb.Primitive_StringValue{
					StringValue: &pb.String{
						Type: &pb.StringType{
							FixedValues: []string{
								"string_fixed_value1",
								"string_fixed_value2",
							},
						},
					},
				},
			},
		},
	}

	// The empty refMap should not affect GetFillableArgs on an arg with fixed values.
	v := NewRefMapView(NewRefMap([]*pb.Method{}), []*pb.MethodTemplate{})
	if v.GetFillableArgs(arg) != nil {
		t.Errorf("Expected to not be able to fill non-free arg with fixed values, got true")
	}
}

// Special case: a non-free arg with a single fixed value is effectively free,
// thus fillable.
func TestGetFillableArgsNonFreeArgWithSingleFixedValue(t *testing.T) {
	arg := &pb.Data{
		Value: &pb.Data_Primitive{
			Primitive: &pb.Primitive{
				TypeHint: "string_type",
				Value: &pb.Primitive_StringValue{
					StringValue: &pb.String{
						Type: &pb.StringType{
							FixedValues: []string{
								"string_fixed_value1",
							},
						},
					},
				},
			},
		},
	}

	// The empty refMap should not affect GetFillableArgs on an arg with fixed values.
	v := NewRefMapView(NewRefMap([]*pb.Method{}), []*pb.MethodTemplate{})
	if diff := cmp.Diff([]*pb.Data{arg}, v.GetFillableArgs(arg), diffArgsOptions...); diff != "" {
		t.Errorf("Expected to be able to fill non-free arg with single fixed value, got diff:\n%s", diff)
	}
}

func TestGetFillableArgsOneOf(t *testing.T) {
	arg := &pb.Data{
		Value: &pb.Data_Oneof{
			&pb.OneOf{
				Options: map[string]*pb.Data{
					"p1": mkPrimitive(p1, nil),
					"p2": mkPrimitive(p2, nil),
					"p3": mkPrimitive(p3, nil),
				},
			},
		},
		Meta: meta1,
	}

	// Don't expect p2 as an option since it's not free.
	expected := []*pb.Data{
		mkPrimitive(p1, meta1),
		mkPrimitive(p3, meta1),
	}

	v := NewRefMapView(NewRefMap([]*pb.Method{}), []*pb.MethodTemplate{})
	if diff := cmp.Diff(expected, v.GetFillableArgs(arg), diffArgsOptions...); diff != "" {
		t.Errorf("Expected 2 fillable args from oneof, got diff:\n%s", diff)
	}
}

func TestGetFillableArgsOneOfInStruct(t *testing.T) {
	oneof := &pb.Data{
		Value: &pb.Data_Oneof{
			&pb.OneOf{
				Options: map[string]*pb.Data{
					"p1": mkPrimitive(p1, nil),
					"p2": mkPrimitive(p2, nil),
					"p3": mkPrimitive(p3, nil),
				},
			},
		},
	}

	arg := mkStruct(map[string]*pb.Data{
		"arg1": oneof,
		"arg2": oneof,
	}, meta1)

	// Don't expect p2 as an option since it's not free.
	expected := []*pb.Data{
		mkStruct(map[string]*pb.Data{
			"arg1": mkPrimitive(p1, nil),
			"arg2": mkPrimitive(p1, nil),
		}, meta1),
		mkStruct(map[string]*pb.Data{
			"arg1": mkPrimitive(p1, nil),
			"arg2": mkPrimitive(p3, nil),
		}, meta1),
		mkStruct(map[string]*pb.Data{
			"arg1": mkPrimitive(p3, nil),
			"arg2": mkPrimitive(p1, nil),
		}, meta1),
		mkStruct(map[string]*pb.Data{
			"arg1": mkPrimitive(p3, nil),
			"arg2": mkPrimitive(p3, nil),
		}, meta1),
	}

	v := NewRefMapView(NewRefMap([]*pb.Method{}), []*pb.MethodTemplate{})
	if diff := cmp.Diff(expected, v.GetFillableArgs(arg), diffArgsOptions...); diff != "" {
		t.Errorf("Expected 2 fillable args from oneof, got diff:\n%s", diff)
	}
}
