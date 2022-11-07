package traefik_auth0_middleware

import (
	"reflect"
	"testing"
)

func Test_getTokenData(t *testing.T) {
	testValue := map[string]interface{}{
		"key1": "value1",
		"key2": map[string]interface{}{
			"key2_depth1": "value2_depth1",
		},
		"key3": map[string]interface{}{
			"key3_depth1": map[string]interface{}{
				"key3_depth2": "value3_depth2",
			},
		},
	}
	type args struct {
		keys []string
		v    map[string]interface{}
	}
	tests := []struct {
		name string
		args args
		want interface{}
	}{
		{
			name: "test no keys",
			args: args{
				keys: []string{},
				v:    testValue,
			},
			want: testValue,
		},
		{
			name: "test single depth",
			args: args{
				keys: []string{"key1"},
				v:    testValue,
			},
			want: "value1",
		},
		{
			name: "test depth",
			args: args{
				keys: []string{"key2.key2_depth1"},
				v:    testValue,
			},
			want: "value2_depth1",
		},
		{
			name: "test depth 2+",
			args: args{
				keys: []string{"key3.key3_depth1.key3_depth2"},
				v:    testValue,
			},
			want: "value3_depth2",
		},
		{
			name: "test multiple keys",
			args: args{
				keys: []string{"key1", "key2"},
				v:    testValue,
			},
			want: map[string]interface{}{
				"key1": "value1",
				"key2": map[string]interface{}{
					"key2_depth1": "value2_depth1",
				},
			},
		},
		{
			name: "test multiple keys with depth",
			args: args{
				keys: []string{"key1", "key2.key2_depth1"},
				v:    testValue,
			},
			want: map[string]interface{}{
				"key1":             "value1",
				"key2.key2_depth1": "value2_depth1",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getTokenData(tt.args.keys, tt.args.v); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getTokenData() = %v, want %v", got, tt.want)
			}
		})
	}
}
